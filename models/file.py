# Manages file metadata and related database operations.
"""File-transfer records for CipherLock (Phase 7).

All SQL is parameterized. Authorization is enforced *in the query*: every
accessor takes the acting user's ID and only returns rows where that user is the
sender and/or the recipient, so callers cannot accidentally leak another user's
file. Admins receive no special access.

Mapping of the Phase 6 package onto the ``files`` table:

    package["sender_id"]            -> files.sender_id
    package["receiver_id"]          -> files.receiver_id
    package["original_filename"]    -> files.original_filename (sanitized)
    (random UUID)                   -> files.encrypted_filename  (<uuid4>.bin)
    package["wrapped_key"]          -> files.encrypted_session_key (BLOB)
    package["nonce"]                -> files.nonce (BLOB)
    package["signature"]            -> files.signature (BLOB)
    package["sender_cert_pem"]      -> files.sender_certificate (BLOB)
    package["ciphertext_sha256_hex"]-> files.ciphertext_sha256
    package["version"]              -> files.package_version      (Phase 7 column)
    package["sender_cert_serial"]   -> files.sender_cert_serial   (Phase 7 column, TEXT)
    package["ciphertext_with_tag"]  -> <ENCRYPTED_STORAGE_DIR>/<encrypted_filename>
"""
from __future__ import annotations

import sqlite3
from typing import Any

from database.db import get_db
from models import storage

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
STATUS_PENDING = "pending"

# Fields never selected for listings: wrapped key, nonce, signature, certificate.
_LIST_COLUMNS = """
    f.id, f.sender_id, f.receiver_id, f.original_filename, f.encrypted_filename,
    f.status, f.created_at,
    s.name AS sender_name, s.email AS sender_email,
    r.name AS receiver_name, r.email AS receiver_email
"""
_LIST_FROM = """
    FROM files f
    JOIN users s ON s.id = f.sender_id
    JOIN users r ON r.id = f.receiver_id
"""


class StoredPackageError(Exception):
    """A database row does not contain everything needed to rebuild its package."""


def _like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def create_file_record(
    *,
    sender_id: int,
    receiver_id: int,
    original_filename: str,
    encrypted_filename: str,
    package: dict[str, Any],
    client_request_id: str | None = None,
    commit: bool = False,
) -> int:
    """Insert a file row from a Phase 6 package. Does not commit by default."""
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO files (
            sender_id, receiver_id, original_filename, encrypted_filename,
            encrypted_session_key, nonce, signature, sender_certificate,
            ciphertext_sha256, status, package_version, sender_cert_serial,
            client_request_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender_id,
            receiver_id,
            original_filename,
            encrypted_filename,
            package["wrapped_key"],
            package["nonce"],
            package["signature"],
            package["sender_cert_pem"],
            package["ciphertext_sha256_hex"],
            STATUS_PENDING,
            package["version"],
            str(package["sender_cert_serial"]),
            client_request_id,
        ),
    )
    if commit:
        db.commit()
    return cursor.lastrowid


def _list(user_column: str, user_id: int, query: str | None, limit: int, offset: int):
    limit = max(1, min(int(limit), MAX_PAGE_SIZE))
    offset = max(0, int(offset))
    where = f"WHERE f.{user_column} = ?"
    params: list[Any] = [user_id]
    if query:
        pattern = _like_pattern(query)
        where += (
            " AND (f.original_filename LIKE ? ESCAPE '\\'"
            " OR s.name LIKE ? ESCAPE '\\' OR s.email LIKE ? ESCAPE '\\'"
            " OR r.name LIKE ? ESCAPE '\\' OR r.email LIKE ? ESCAPE '\\')"
        )
        params += [pattern] * 5
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) {_LIST_FROM} {where}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT {_LIST_COLUMNS} {_LIST_FROM} {where} "
        "ORDER BY f.created_at DESC, f.id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return rows, total


def list_sent(user_id: int, query: str | None = None,
              limit: int = DEFAULT_PAGE_SIZE, offset: int = 0):
    """Files whose sender is ``user_id``; newest first. Returns ``(rows, total)``."""
    return _list("sender_id", user_id, query, limit, offset)


def list_received(user_id: int, query: str | None = None,
                  limit: int = DEFAULT_PAGE_SIZE, offset: int = 0):
    """Files addressed to ``user_id``; newest first. Returns ``(rows, total)``."""
    return _list("receiver_id", user_id, query, limit, offset)


def count_sent(user_id: int) -> int:
    return get_db().execute(
        "SELECT COUNT(*) FROM files WHERE sender_id = ?", (user_id,)
    ).fetchone()[0]


def count_received(user_id: int) -> int:
    return get_db().execute(
        "SELECT COUNT(*) FROM files WHERE receiver_id = ?", (user_id,)
    ).fetchone()[0]


_DETAIL_EXTRA = ", f.ciphertext_sha256, f.package_version, f.sender_cert_serial"


def _get(file_id: int, user_clause: str, user_params: tuple[int, ...]) -> sqlite3.Row | None:
    """Fetch one file row; ``user_clause`` is a fixed internal SQL fragment."""
    return get_db().execute(
        f"SELECT {_LIST_COLUMNS}{_DETAIL_EXTRA} {_LIST_FROM} "
        f"WHERE f.id = ? AND ({user_clause})",
        (file_id, *user_params),
    ).fetchone()


def get_file_for_participant(file_id: int, user_id: int) -> sqlite3.Row | None:
    """Metadata row if ``user_id`` is the sender or recipient, else None."""
    return _get(file_id, "f.sender_id = ? OR f.receiver_id = ?", (user_id, user_id))


def get_file_for_sender(file_id: int, user_id: int) -> sqlite3.Row | None:
    return _get(file_id, "f.sender_id = ?", (user_id,))


def get_file_for_receiver(file_id: int, user_id: int) -> sqlite3.Row | None:
    return _get(file_id, "f.receiver_id = ?", (user_id,))


def get_file_by_request_id(sender_id: int, client_request_id: str) -> sqlite3.Row | None:
    """Look up a previous upload by the sender's idempotency key."""
    return get_db().execute(
        f"SELECT {_LIST_COLUMNS}{_DETAIL_EXTRA} {_LIST_FROM} "
        "WHERE f.sender_id = ? AND f.client_request_id = ?",
        (sender_id, client_request_id),
    ).fetchone()


def file_to_dict(row: sqlite3.Row, *, include_digest: bool = False,
                 include_storage_status: bool = False) -> dict[str, Any]:
    """Serialize a row into safe, client-facing metadata.

    Never includes the wrapped key, nonce, signature, certificate, storage
    filename or any filesystem path.
    """
    size = storage.payload_size(row["encrypted_filename"])
    data: dict[str, Any] = {
        "id": row["id"],
        "original_filename": row["original_filename"],
        "status": row["status"],
        "created_at": row["created_at"],
        # ciphertext = plaintext + 16-byte GCM tag
        "size_bytes": max(size - 16, 0) if size is not None else None,
        "sender": {"id": row["sender_id"], "name": row["sender_name"], "email": row["sender_email"]},
        "receiver": {"id": row["receiver_id"], "name": row["receiver_name"], "email": row["receiver_email"]},
    }
    keys = row.keys()
    if include_digest and "ciphertext_sha256" in keys:
        data["ciphertext_sha256"] = row["ciphertext_sha256"]
        data["package_version"] = row["package_version"]
        data["sender_cert_serial"] = row["sender_cert_serial"]
    if include_storage_status and "ciphertext_sha256" in keys:
        data["storage_status"] = storage.inspect_payload(
            row["encrypted_filename"], row["ciphertext_sha256"]
        )
    return data


def reconstruct_package(file_id: int, user_id: int) -> dict[str, Any]:
    """Rebuild the exact Phase 6 package dict for a file the user may access.

    Intended for Phase 8 (verify/open). Raises ``LookupError`` if the file does
    not exist or the user is not a participant, ``StoredPackageError`` if the row
    lacks required fields, and ``storage.StorageError`` subclasses if the payload
    is missing/corrupt. The returned ``ciphertext_sha256_hex`` is the *recorded*
    (signed) digest; ``verify_package`` recomputes the real one from the bytes.
    """
    row = get_db().execute(
        """
        SELECT id, sender_id, receiver_id, original_filename, encrypted_filename,
               encrypted_session_key, nonce, signature, sender_certificate,
               ciphertext_sha256, package_version, sender_cert_serial
        FROM files WHERE id = ? AND (sender_id = ? OR receiver_id = ?)
        """,
        (file_id, user_id, user_id),
    ).fetchone()
    if row is None:
        raise LookupError("File not found.")
    for column in ("encrypted_session_key", "nonce", "signature", "sender_certificate",
                   "ciphertext_sha256", "sender_cert_serial"):
        if row[column] is None:
            raise StoredPackageError("Stored package metadata is incomplete.")
    try:
        serial = int(row["sender_cert_serial"])
    except (TypeError, ValueError):
        raise StoredPackageError("Stored package metadata is invalid.") from None
    return {
        "version": row["package_version"],
        "sender_id": row["sender_id"],
        "receiver_id": row["receiver_id"],
        "original_filename": row["original_filename"],
        "nonce": bytes(row["nonce"]),
        "wrapped_key": bytes(row["encrypted_session_key"]),
        "ciphertext_with_tag": storage.read_ciphertext(row["encrypted_filename"]),
        "ciphertext_sha256_hex": row["ciphertext_sha256"],
        "signature": bytes(row["signature"]),
        "sender_cert_pem": bytes(row["sender_certificate"]),
        "sender_cert_serial": serial,
    }
