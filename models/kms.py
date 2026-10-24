"""Phase 10 – KMS service layer for key lifecycle management.

Manages the full KEK/DEK lifecycle:
- KEK creation, rotation, compromise, recovery, destruction
- DEK registration, wrapping, unwrapping, rewrapping
- Rotation policy enforcement and auto-rotation checks
- KMS audit logging

All database operations use parameterized queries. The master key is
derived on-demand from the application SECRET_KEY and never stored.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import current_app

from crypto.kms import (
    DEKWrapError,
    KEKProtectionError,
    ProtectedKEK,
    WrappedDEK,
    derive_master_key,
    generate_dek,
    generate_kek,
    protect_kek,
    rewrap_dek,
    unprotect_kek,
    unwrap_dek,
    wrap_dek,
)
from database.db import get_db

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEK_STATUS_ACTIVE = "active"
KEK_STATUS_ROTATED = "rotated"
KEK_STATUS_COMPROMISED = "compromised"
KEK_STATUS_DESTROYED = "destroyed"

KMS_ACTIONS = {
    "kek_created",
    "kek_rotated",
    "kek_compromised",
    "kek_recovered",
    "kek_destroyed",
    "dek_registered",
    "dek_rewrapped",
    "dek_rewrap_batch",
    "policy_updated",
    "auto_rotation_check",
    "auto_rotation_triggered",
    "master_key_verified",
}

# The master salt is stored once and reused for all master key derivations.
# It is generated on first KMS initialization and persisted in the KMS config.
_MASTER_SALT_KEY = "kms_master_salt"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KMSError(Exception):
    """General KMS service error."""


class KEKNotFoundError(KMSError):
    """No KEK found for the requested version."""


class NoActiveKEKError(KMSError):
    """No active KEK is available."""


class PolicyViolationError(KMSError):
    """Operation violates the configured rotation policy."""


# ---------------------------------------------------------------------------
# Master key management
# ---------------------------------------------------------------------------

def _get_or_create_master_salt(db: sqlite3.Connection) -> bytes:
    """Retrieve or generate the persistent master key salt.

    Stored in the rotation_policies table description field to avoid adding
    another table. On first call, a fresh 32-byte salt is generated and stored.
    """
    row = db.execute(
        "SELECT description FROM rotation_policies WHERE key_type = 'kek'"
    ).fetchone()

    if row and row["description"]:
        try:
            salt = bytes.fromhex(row["description"])
            if len(salt) >= 16:
                return salt
        except (ValueError, TypeError):
            pass

    # Generate a new master salt.
    import os
    salt = os.urandom(32)
    db.execute(
        "UPDATE rotation_policies SET description = ? WHERE key_type = 'kek'",
        (salt.hex(),),
    )
    db.commit()
    return salt


def get_master_key() -> bytes:
    """Derive the master key from the application SECRET_KEY.

    The master salt is persisted in the database so the same master key is
    derived across application restarts.
    """
    db = get_db()
    salt = _get_or_create_master_salt(db)
    secret_key = current_app.config["SECRET_KEY"]
    master_key, _ = derive_master_key(secret_key, salt)
    return master_key


# ---------------------------------------------------------------------------
# KMS audit logging
# ---------------------------------------------------------------------------

def log_kms_event(
    action: str,
    kek_version: int | None = None,
    detail: str = "",
    user_id: int | None = None,
    commit: bool = True,
) -> None:
    """Record a KMS audit event."""
    db = get_db()
    db.execute(
        "INSERT INTO kms_audit_log (user_id, action, kek_version, detail) "
        "VALUES (?, ?, ?, ?)",
        (user_id, action, kek_version, detail),
    )
    if commit:
        db.commit()


def list_kms_audit(
    limit: int = 50,
    offset: int = 0,
    action_filter: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return KMS audit entries newest-first."""
    db = get_db()
    where = ""
    params: list[Any] = []
    if action_filter:
        where = "WHERE action = ?"
        params.append(action_filter)

    total = db.execute(
        f"SELECT COUNT(*) FROM kms_audit_log {where}", params
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT id, user_id, action, kek_version, detail, created_at "
        f"FROM kms_audit_log {where} ORDER BY created_at DESC, id DESC "
        f"LIMIT ? OFFSET ?",
        [*params, min(limit, 200), max(offset, 0)],
    ).fetchall()

    entries = [
        {
            "id": r["id"],
            "user_id": r["user_id"],
            "action": r["action"],
            "kek_version": r["kek_version"],
            "detail": r["detail"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return entries, total


# ---------------------------------------------------------------------------
# KEK management
# ---------------------------------------------------------------------------

def _next_kek_version(db: sqlite3.Connection) -> int:
    """Return the next KEK version number."""
    row = db.execute("SELECT MAX(version) FROM kek_versions").fetchone()
    return (row[0] or 0) + 1


def create_kek(
    user_id: int | None = None,
    description: str = "",
    rotation_days: int | None = None,
) -> dict[str, Any]:
    """Generate and store a new KEK version.

    If there is already an active KEK, it is moved to 'rotated' status.
    Returns the new KEK version metadata.
    """
    db = get_db()
    master_key = get_master_key()
    version = _next_kek_version(db)

    # Generate and protect the KEK.
    raw_kek = generate_kek()
    protected = protect_kek(raw_kek, master_key, version)
    del raw_kek  # clear plaintext from memory

    # Compute expiry.
    expires_at = None
    if rotation_days is None:
        policy = get_rotation_policy()
        rotation_days = policy["rotation_interval_days"]
    if rotation_days and rotation_days > 0:
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=rotation_days)
        ).strftime("%Y-%m-%dT%H:%M:%fZ")

    # Demote the current active KEK.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%fZ")
    db.execute(
        "UPDATE kek_versions SET status = ?, rotated_at = ? WHERE status = ?",
        (KEK_STATUS_ROTATED, now, KEK_STATUS_ACTIVE),
    )

    # Insert the new active KEK.
    db.execute(
        """
        INSERT INTO kek_versions
            (version, encrypted_kek, nonce, salt, status, expires_at, created_by, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            version,
            protected.encrypted_kek,
            protected.nonce,
            protected.salt,
            KEK_STATUS_ACTIVE,
            expires_at,
            user_id,
            description,
        ),
    )

    log_kms_event(
        "kek_created", kek_version=version,
        detail=f"New KEK v{version} created",
        user_id=user_id, commit=False,
    )
    db.commit()

    return {
        "version": version,
        "status": KEK_STATUS_ACTIVE,
        "expires_at": expires_at,
        "created_at": now,
    }


def get_active_kek_row() -> sqlite3.Row | None:
    """Return the currently active KEK row, or None."""
    db = get_db()
    return db.execute(
        "SELECT * FROM kek_versions WHERE status = ? ORDER BY version DESC LIMIT 1",
        (KEK_STATUS_ACTIVE,),
    ).fetchone()


def get_active_kek() -> tuple[bytes, int]:
    """Return ``(plaintext_kek, version)`` for the active KEK.

    Raises ``NoActiveKEKError`` if no active KEK exists.
    """
    row = get_active_kek_row()
    if row is None:
        raise NoActiveKEKError("No active KEK. Run KMS initialization first.")

    master_key = get_master_key()
    protected = ProtectedKEK(
        encrypted_kek=bytes(row["encrypted_kek"]),
        nonce=bytes(row["nonce"]),
        salt=bytes(row["salt"]),
    )
    kek = unprotect_kek(protected, master_key, row["version"])
    return kek, row["version"]


def get_kek_by_version(version: int) -> tuple[bytes, dict[str, Any]]:
    """Return ``(plaintext_kek, metadata)`` for a specific KEK version.

    Raises ``KEKNotFoundError`` if not found, ``KMSError`` if the key is
    destroyed.
    """
    db = get_db()
    row = db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise KEKNotFoundError(f"KEK version {version} not found.")
    if row["status"] == KEK_STATUS_DESTROYED:
        raise KMSError(f"KEK version {version} has been destroyed and cannot be used.")

    master_key = get_master_key()
    protected = ProtectedKEK(
        encrypted_kek=bytes(row["encrypted_kek"]),
        nonce=bytes(row["nonce"]),
        salt=bytes(row["salt"]),
    )
    kek = unprotect_kek(protected, master_key, version)
    meta = _kek_row_to_dict(row)
    return kek, meta


def list_kek_versions() -> list[dict[str, Any]]:
    """Return all KEK versions with their metadata (no plaintext keys)."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM kek_versions ORDER BY version DESC"
    ).fetchall()
    return [_kek_row_to_dict(r) for r in rows]


def _kek_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Serialize a KEK row to a safe dict (never includes key material)."""
    db = get_db()
    dek_count = db.execute(
        "SELECT COUNT(*) FROM dek_registry WHERE kek_version_id = ?",
        (row["id"],),
    ).fetchone()[0]

    return {
        "id": row["id"],
        "version": row["version"],
        "status": row["status"],
        "created_at": row["created_at"],
        "rotated_at": row["rotated_at"],
        "expires_at": row["expires_at"],
        "compromised_at": row["compromised_at"],
        "destroyed_at": row["destroyed_at"],
        "created_by": row["created_by"],
        "description": row["description"],
        "dek_count": dek_count,
    }


# ---------------------------------------------------------------------------
# KEK rotation
# ---------------------------------------------------------------------------

def rotate_kek(
    user_id: int | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Rotate to a new KEK version. The old active KEK becomes 'rotated'.

    Does NOT automatically rewrap DEKs – call ``rewrap_all_deks()`` separately
    to complete the rotation lifecycle.
    """
    result = create_kek(user_id=user_id, description=description or "Scheduled rotation")
    log_kms_event(
        "kek_rotated", kek_version=result["version"],
        detail=f"KEK rotated to v{result['version']}",
        user_id=user_id,
    )
    return result


# ---------------------------------------------------------------------------
# Key compromise & recovery
# ---------------------------------------------------------------------------

def compromise_kek(
    version: int,
    user_id: int | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Mark a KEK version as compromised.

    This prevents the key from being used for new wrapping operations.
    The admin should call ``rewrap_all_deks()`` to move DEKs off this key.
    """
    db = get_db()
    row = db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise KEKNotFoundError(f"KEK version {version} not found.")
    if row["status"] == KEK_STATUS_DESTROYED:
        raise KMSError("Cannot compromise a destroyed key.")
    if row["status"] == KEK_STATUS_COMPROMISED:
        raise KMSError("Key is already marked as compromised.")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%fZ")
    db.execute(
        "UPDATE kek_versions SET status = ?, compromised_at = ? WHERE version = ?",
        (KEK_STATUS_COMPROMISED, now, version),
    )
    log_kms_event(
        "kek_compromised", kek_version=version,
        detail=f"Compromised: {reason}" if reason else "Key marked as compromised",
        user_id=user_id, commit=False,
    )
    db.commit()

    # Auto-rotate if the compromised key was active.
    result = _kek_row_to_dict(db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone())

    if get_active_kek_row() is None:
        new = create_kek(
            user_id=user_id,
            description=f"Emergency rotation after v{version} compromise",
        )
        result["new_active_version"] = new["version"]

    return result


def recover_from_compromise(
    version: int,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Move a compromised KEK to 'rotated' status after remediation.

    This only changes the status label; the key should have already been
    rotated away from and all DEKs rewrapped.
    """
    db = get_db()
    row = db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise KEKNotFoundError(f"KEK version {version} not found.")
    if row["status"] != KEK_STATUS_COMPROMISED:
        raise KMSError("Only compromised keys can be recovered.")

    # Verify no DEKs still reference this key.
    dek_count = db.execute(
        "SELECT COUNT(*) FROM dek_registry WHERE kek_version_id = ?",
        (row["id"],),
    ).fetchone()[0]
    if dek_count > 0:
        raise KMSError(
            f"Cannot recover: {dek_count} DEK(s) still wrapped by this key. "
            "Rewrap them first."
        )

    db.execute(
        "UPDATE kek_versions SET status = ? WHERE version = ?",
        (KEK_STATUS_ROTATED, version),
    )
    log_kms_event(
        "kek_recovered", kek_version=version,
        detail="Recovered from compromise – no DEKs remain",
        user_id=user_id, commit=False,
    )
    db.commit()
    return _kek_row_to_dict(db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone())


def destroy_kek(
    version: int,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Permanently mark a KEK as destroyed.

    Destroyed KEKs cannot decrypt anything. This is irreversible.
    """
    db = get_db()
    row = db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise KEKNotFoundError(f"KEK version {version} not found.")
    if row["status"] == KEK_STATUS_ACTIVE:
        raise KMSError("Cannot destroy the active KEK. Rotate first.")
    if row["status"] == KEK_STATUS_DESTROYED:
        raise KMSError("Key is already destroyed.")

    dek_count = db.execute(
        "SELECT COUNT(*) FROM dek_registry WHERE kek_version_id = ?",
        (row["id"],),
    ).fetchone()[0]
    if dek_count > 0:
        raise KMSError(
            f"Cannot destroy: {dek_count} DEK(s) still wrapped by this key. "
            "Rewrap them first."
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%fZ")
    db.execute(
        "UPDATE kek_versions SET status = ?, destroyed_at = ? WHERE version = ?",
        (KEK_STATUS_DESTROYED, now, version),
    )
    log_kms_event(
        "kek_destroyed", kek_version=version,
        detail="Key permanently destroyed",
        user_id=user_id, commit=False,
    )
    db.commit()
    return _kek_row_to_dict(db.execute(
        "SELECT * FROM kek_versions WHERE version = ?", (version,)
    ).fetchone())


# ---------------------------------------------------------------------------
# DEK management
# ---------------------------------------------------------------------------

def register_dek(
    file_id: int,
    dek: bytes,
    kek: bytes | None = None,
    kek_version: int | None = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Wrap and store a DEK for a file.

    If ``kek`` / ``kek_version`` are not provided, uses the active KEK.
    """
    db = get_db()

    if kek is None or kek_version is None:
        kek, kek_version = get_active_kek()

    # Find the KEK row id.
    kek_row = db.execute(
        "SELECT id FROM kek_versions WHERE version = ?", (kek_version,)
    ).fetchone()
    if kek_row is None:
        raise KEKNotFoundError(f"KEK version {kek_version} not found.")

    wrapped = wrap_dek(dek, kek, file_id)

    # Upsert: replace if a DEK already exists for this file.
    db.execute(
        """
        INSERT INTO dek_registry (file_id, wrapped_dek, nonce, kek_version_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(file_id) DO UPDATE SET
            wrapped_dek = excluded.wrapped_dek,
            nonce = excluded.nonce,
            kek_version_id = excluded.kek_version_id,
            rewrapped_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        """,
        (file_id, wrapped.wrapped_dek, wrapped.nonce, kek_row["id"]),
    )

    log_kms_event(
        "dek_registered", kek_version=kek_version,
        detail=f"DEK registered for file_id={file_id}",
        user_id=user_id, commit=False,
    )
    db.commit()

    return {
        "file_id": file_id,
        "kek_version": kek_version,
        "status": "wrapped",
    }


def get_dek_for_file(file_id: int) -> tuple[bytes, int]:
    """Return ``(plaintext_dek, kek_version)`` for a file.

    Raises ``KMSError`` if no DEK is registered for the file.
    """
    db = get_db()
    row = db.execute(
        """
        SELECT dr.wrapped_dek, dr.nonce, dr.kek_version_id,
               kv.version, kv.status, kv.encrypted_kek,
               kv.nonce AS kek_nonce, kv.salt AS kek_salt
        FROM dek_registry dr
        JOIN kek_versions kv ON kv.id = dr.kek_version_id
        WHERE dr.file_id = ?
        """,
        (file_id,),
    ).fetchone()

    if row is None:
        raise KMSError(f"No DEK registered for file {file_id}.")
    if row["status"] == KEK_STATUS_DESTROYED:
        raise KMSError("The KEK for this file has been destroyed. Data is irrecoverable.")

    # Decrypt the KEK.
    master_key = get_master_key()
    protected = ProtectedKEK(
        encrypted_kek=bytes(row["encrypted_kek"]),
        nonce=bytes(row["kek_nonce"]),
        salt=bytes(row["kek_salt"]),
    )
    kek = unprotect_kek(protected, master_key, row["version"])

    # Unwrap the DEK.
    wrapped = WrappedDEK(
        wrapped_dek=bytes(row["wrapped_dek"]),
        nonce=bytes(row["nonce"]),
    )
    dek = unwrap_dek(wrapped, kek, file_id)
    del kek

    return dek, row["version"]


def get_dek_info(file_id: int) -> dict[str, Any] | None:
    """Return DEK metadata for a file (no key material)."""
    db = get_db()
    row = db.execute(
        """
        SELECT dr.id, dr.file_id, dr.kek_version_id, dr.created_at, dr.rewrapped_at,
               kv.version AS kek_version, kv.status AS kek_status
        FROM dek_registry dr
        JOIN kek_versions kv ON kv.id = dr.kek_version_id
        WHERE dr.file_id = ?
        """,
        (file_id,),
    ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "file_id": row["file_id"],
        "kek_version": row["kek_version"],
        "kek_status": row["kek_status"],
        "created_at": row["created_at"],
        "rewrapped_at": row["rewrapped_at"],
    }


# ---------------------------------------------------------------------------
# Batch DEK rewrapping
# ---------------------------------------------------------------------------

def rewrap_all_deks(
    target_kek_version: int | None = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Rewrap all DEKs under the specified (or active) KEK.

    Returns a summary of the rewrap operation.
    """
    db = get_db()

    # Determine target KEK.
    if target_kek_version is None:
        target_kek, target_version = get_active_kek()
    else:
        target_kek, _ = get_kek_by_version(target_kek_version)
        target_version = target_kek_version

    target_row = db.execute(
        "SELECT id FROM kek_versions WHERE version = ?", (target_version,)
    ).fetchone()
    if target_row is None:
        raise KEKNotFoundError(f"Target KEK version {target_version} not found.")

    # Find all DEKs NOT already wrapped by the target KEK.
    rows = db.execute(
        """
        SELECT dr.id, dr.file_id, dr.wrapped_dek, dr.nonce, dr.kek_version_id,
               kv.version AS old_version, kv.encrypted_kek AS old_enc_kek,
               kv.nonce AS old_kek_nonce, kv.salt AS old_kek_salt
        FROM dek_registry dr
        JOIN kek_versions kv ON kv.id = dr.kek_version_id
        WHERE dr.kek_version_id != ?
        """,
        (target_row["id"],),
    ).fetchall()

    master_key = get_master_key()
    rewrapped = 0
    failed = 0
    errors: list[str] = []

    for row in rows:
        try:
            # Decrypt the old KEK.
            old_protected = ProtectedKEK(
                encrypted_kek=bytes(row["old_enc_kek"]),
                nonce=bytes(row["old_kek_nonce"]),
                salt=bytes(row["old_kek_salt"]),
            )
            old_kek = unprotect_kek(old_protected, master_key, row["old_version"])

            # Rewrap the DEK.
            old_wrapped = WrappedDEK(
                wrapped_dek=bytes(row["wrapped_dek"]),
                nonce=bytes(row["nonce"]),
            )
            new_wrapped = rewrap_dek(old_wrapped, old_kek, target_kek, row["file_id"])
            del old_kek

            # Update the registry.
            db.execute(
                """
                UPDATE dek_registry
                SET wrapped_dek = ?, nonce = ?, kek_version_id = ?,
                    rewrapped_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ?
                """,
                (new_wrapped.wrapped_dek, new_wrapped.nonce, target_row["id"], row["id"]),
            )
            rewrapped += 1

        except (KEKProtectionError, DEKWrapError) as exc:
            failed += 1
            errors.append(f"file_id={row['file_id']}: {exc}")
            continue

    log_kms_event(
        "dek_rewrap_batch", kek_version=target_version,
        detail=f"Rewrapped {rewrapped} DEKs, {failed} failed",
        user_id=user_id, commit=False,
    )
    db.commit()

    return {
        "target_kek_version": target_version,
        "total": len(rows),
        "rewrapped": rewrapped,
        "failed": failed,
        "errors": errors[:10],  # cap error detail
    }


# ---------------------------------------------------------------------------
# Rotation policy
# ---------------------------------------------------------------------------

def get_rotation_policy() -> dict[str, Any]:
    """Return the current rotation policy."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM rotation_policies WHERE key_type = 'kek'"
    ).fetchone()
    if row is None:
        return {
            "key_type": "kek",
            "rotation_interval_days": 90,
            "auto_rotate": False,
            "max_versions": 10,
        }
    return {
        "key_type": row["key_type"],
        "rotation_interval_days": row["rotation_interval_days"],
        "auto_rotate": bool(row["auto_rotate"]),
        "max_versions": row["max_versions"],
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    }


def update_rotation_policy(
    rotation_interval_days: int | None = None,
    auto_rotate: bool | None = None,
    max_versions: int | None = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Update the KEK rotation policy."""
    db = get_db()
    current = get_rotation_policy()

    if rotation_interval_days is not None:
        if not isinstance(rotation_interval_days, int) or rotation_interval_days < 1:
            raise PolicyViolationError("Rotation interval must be at least 1 day.")
        if rotation_interval_days > 365:
            raise PolicyViolationError("Rotation interval must not exceed 365 days.")
        current["rotation_interval_days"] = rotation_interval_days

    if auto_rotate is not None:
        current["auto_rotate"] = bool(auto_rotate)

    if max_versions is not None:
        if not isinstance(max_versions, int) or max_versions < 2:
            raise PolicyViolationError("Must keep at least 2 key versions.")
        if max_versions > 100:
            raise PolicyViolationError("Cannot keep more than 100 versions.")
        current["max_versions"] = max_versions

    # Preserve the master salt stored in description.
    db.execute(
        """
        UPDATE rotation_policies
        SET rotation_interval_days = ?,
            auto_rotate = ?,
            max_versions = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            updated_by = ?
        WHERE key_type = 'kek'
        """,
        (
            current["rotation_interval_days"],
            1 if current["auto_rotate"] else 0,
            current["max_versions"],
            user_id,
        ),
    )

    log_kms_event(
        "policy_updated", detail=f"interval={current['rotation_interval_days']}d "
        f"auto={current['auto_rotate']} max={current['max_versions']}",
        user_id=user_id, commit=False,
    )
    db.commit()
    return get_rotation_policy()


# ---------------------------------------------------------------------------
# Auto-rotation check
# ---------------------------------------------------------------------------

def check_rotation_needed() -> dict[str, Any]:
    """Check if automatic KEK rotation is needed.

    Returns a dict with rotation status information.
    """
    policy = get_rotation_policy()
    active = get_active_kek_row()

    result: dict[str, Any] = {
        "rotation_needed": False,
        "auto_rotate_enabled": policy["auto_rotate"],
        "reason": None,
    }

    if active is None:
        result["rotation_needed"] = True
        result["reason"] = "No active KEK exists."
        return result

    # Check expiry.
    if active["expires_at"]:
        try:
            expires = datetime.fromisoformat(active["expires_at"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now >= expires:
                result["rotation_needed"] = True
                result["reason"] = f"KEK v{active['version']} has expired."
            else:
                result["days_until_expiry"] = (expires - now).days
        except (ValueError, TypeError):
            pass

    # Check age against policy.
    if not result["rotation_needed"] and active["created_at"]:
        try:
            created = datetime.fromisoformat(active["created_at"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days >= policy["rotation_interval_days"]:
                result["rotation_needed"] = True
                result["reason"] = (
                    f"KEK v{active['version']} is {age_days} days old "
                    f"(policy: {policy['rotation_interval_days']} days)."
                )
            else:
                result["days_since_creation"] = age_days
        except (ValueError, TypeError):
            pass

    return result


def perform_auto_rotation(user_id: int | None = None) -> dict[str, Any] | None:
    """If auto-rotation is enabled and needed, rotate the KEK.

    Returns the rotation result or None if no rotation was needed.
    """
    check = check_rotation_needed()
    policy = get_rotation_policy()

    log_kms_event(
        "auto_rotation_check",
        detail=f"needed={check['rotation_needed']} reason={check.get('reason', 'N/A')}",
        user_id=user_id,
    )

    if not check["rotation_needed"] or not policy["auto_rotate"]:
        return None

    result = rotate_kek(user_id=user_id, description="Automatic rotation")
    log_kms_event(
        "auto_rotation_triggered", kek_version=result["version"],
        detail="Auto-rotation completed",
        user_id=user_id,
    )
    return result


# ---------------------------------------------------------------------------
# KMS status summary
# ---------------------------------------------------------------------------

def get_kms_status() -> dict[str, Any]:
    """Return a comprehensive KMS status summary."""
    db = get_db()

    active = get_active_kek_row()
    total_keks = db.execute("SELECT COUNT(*) FROM kek_versions").fetchone()[0]
    total_deks = db.execute("SELECT COUNT(*) FROM dek_registry").fetchone()[0]
    compromised = db.execute(
        "SELECT COUNT(*) FROM kek_versions WHERE status = ?",
        (KEK_STATUS_COMPROMISED,),
    ).fetchone()[0]

    status: dict[str, Any] = {
        "initialized": active is not None,
        "active_kek_version": active["version"] if active else None,
        "total_kek_versions": total_keks,
        "total_deks": total_deks,
        "compromised_keks": compromised,
        "policy": get_rotation_policy(),
    }

    if active:
        status["active_kek"] = _kek_row_to_dict(active)
        rotation_check = check_rotation_needed()
        status["rotation_check"] = rotation_check

    return status


# ---------------------------------------------------------------------------
# KMS initialization (ensure schema and first KEK exist)
# ---------------------------------------------------------------------------

def init_kms_schema(db: sqlite3.Connection) -> None:
    """Create KMS tables if they don't exist (idempotent)."""
    schema_path = Path(__file__).parent.parent / "database" / "schema_kms.sql"
    if schema_path.exists():
        db.executescript(schema_path.read_text(encoding="utf-8"))


def ensure_kms_initialized() -> dict[str, Any]:
    """Ensure the KMS is initialized with at least one active KEK.

    Called during application startup. Creates the initial KEK if none exists.
    """
    db = get_db()
    init_kms_schema(db)

    active = get_active_kek_row()
    if active is not None:
        return {"status": "already_initialized", "active_version": active["version"]}

    result = create_kek(description="Initial KMS bootstrap")
    return {"status": "initialized", "active_version": result["version"]}
