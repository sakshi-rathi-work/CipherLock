"""Administrator certificate, account, audit, and local demo endpoints."""
from __future__ import annotations

import base64
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash

from crypto.ca import issue_user_certificate, load_ca, revoke_certificate
from crypto.certificates import verify_certificate
from crypto.rsa import load_public_key, public_key_fingerprint
from database.db import get_db
from models import storage
from models.activity import log_activity
from models.user import set_user_active
from routes import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")
_MAX_ACTIVITY_LIMIT = 100
_CERTIFICATE_STATUSES = {"active", "revoked", "expired"}


def _demo_mode_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Hide every lab endpoint unless the local demonstration mode is enabled."""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not current_app.config.get("DEMO_MODE", False):
            return jsonify({"error": "Not found"}), 404
        return f(*args, **kwargs)
    return decorated_function


def _backup_paths(file_id: int) -> tuple[Path, Path]:
    directory = (Path(current_app.config["STORAGE_DIR"]) / ".demo-backups").resolve()
    directory.mkdir(parents=True, exist_ok=True)
    stem = str(file_id)
    return directory / f"{stem}.bin", directory / f"{stem}.json"


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _load_lab_file(file_id: int):
    return get_db().execute(
        """
        SELECT id, original_filename, encrypted_filename, signature,
               sender_certificate, sender_id
        FROM files WHERE id = ?
        """,
        (file_id,),
    ).fetchone()


def _ensure_backup(row) -> tuple[Path, Path]:
    payload_path = storage.resolve_storage_path(row["encrypted_filename"])
    backup_payload, backup_manifest = _backup_paths(row["id"])
    if backup_payload.exists() or backup_manifest.exists():
        if backup_payload.is_file() and backup_manifest.is_file():
            return backup_payload, backup_manifest
        raise RuntimeError("Demo backup is incomplete; refusing to overwrite it.")

    metadata = {
        "original_filename": row["original_filename"],
        "signature": base64.b64encode(bytes(row["signature"])).decode("ascii"),
        "sender_certificate": base64.b64encode(bytes(row["sender_certificate"])).decode("ascii"),
    }
    _atomic_write(backup_payload, payload_path.read_bytes())
    try:
        _atomic_write(backup_manifest, json.dumps(metadata, separators=(",", ":")).encode("utf-8"))
    except BaseException:
        backup_payload.unlink(missing_ok=True)
        raise
    return backup_payload, backup_manifest


def _audit_demo_action(file_id: int, action: str) -> None:
    log_activity(
        g.current_user["id"],
        "SIMULATED ATTACK",
        f"action={action} file_id={file_id}",
    )


def _requested_lab_file_id() -> int | None:
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or type(data.get("file_id")) is not int
        or data["file_id"] < 1
    ):
        return None
    return data["file_id"]


def _tamper(file_id: int, action: str):
    row = _load_lab_file(file_id)
    if row is None:
        return jsonify({"error": "File not found"}), 404

    backup_payload, _ = _ensure_backup(row)
    payload_path = storage.resolve_storage_path(row["encrypted_filename"])
    if action == "tamper-ciphertext":
        payload = bytearray(payload_path.read_bytes())
        if not payload:
            return jsonify({"error": "Stored ciphertext is empty"}), 409
        payload[len(payload) // 2] ^= 1
        _atomic_write(payload_path, bytes(payload))
    elif action == "tamper-metadata":
        current = row["original_filename"]
        replacement = f"tampered-{current}"[:255]
        get_db().execute("UPDATE files SET original_filename = ? WHERE id = ?", (replacement, file_id))
        get_db().commit()
    elif action == "tamper-signature":
        signature = bytes(row["signature"])
        if not signature:
            return jsonify({"error": "Stored signature is empty"}), 409
        get_db().execute(
            "UPDATE files SET signature = ? WHERE id = ?",
            (secrets.token_bytes(len(signature)), file_id),
        )
        get_db().commit()
    elif action == "swap-cert":
        try:
            sender_cert = x509.load_pem_x509_certificate(bytes(row["sender_certificate"]))
        except ValueError:
            return jsonify({"error": "The stored sender certificate cannot be parsed"}), 409
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Demo CA")])
        now = datetime.now(timezone.utc)
        rogue_ca = (
            x509.CertificateBuilder()
            .subject_name(rogue_name)
            .issuer_name(rogue_name)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(rogue_key, hashes.SHA256())
        )
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(sender_cert.subject)
            .issuer_name(rogue_ca.subject)
            .public_key(sender_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.RFC822Name(sender_cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value)
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(rogue_key, hashes.SHA256())
        )
        get_db().execute(
            "UPDATE files SET sender_certificate = ? WHERE id = ?",
            (rogue_cert.public_bytes(serialization.Encoding.PEM), file_id),
        )
        get_db().commit()
    else:
        raise ValueError("Unknown demonstration action.")

    _audit_demo_action(file_id, action)
    messages = {
        "tamper-ciphertext": "Ciphertext tampered",
        "tamper-metadata": "Metadata tampered",
        "tamper-signature": "Signature tampered",
        "swap-cert": "Untrusted certificate substituted",
    }
    return jsonify({
        "message": messages[action],
        "status_url": f"/files/{file_id}/verify",
    }), 200


def _certificate_status(row) -> str:
    if row["status"] == "revoked":
        return "revoked"
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return "expired" if expires_at <= datetime.now(timezone.utc) else "active"


@admin_bp.get("/ca-info")
@admin_required
def ca_info():
    """Return non-secret Root CA metadata and certificate statistics."""
    try:
        _, ca_certificate = load_ca()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return jsonify({"error": f"Root CA unavailable: {exc}"}), 503

    db = get_db()
    certificate_rows = db.execute("SELECT status, expires_at FROM certificates").fetchall()
    stats: dict[str, int] = {}
    for row in certificate_rows:
        status = _certificate_status(row)
        stats[status] = stats.get(status, 0) + 1
    return jsonify({
        "subject": ca_certificate.subject.rfc4514_string(),
        "serial": ca_certificate.serial_number,
        "not_valid_before": ca_certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": ca_certificate.not_valid_after_utc.isoformat(),
        "key_size": ca_certificate.public_key().key_size,
        "certificate_count": sum(stats.values()),
        "active_count": stats.get("active", 0),
        "revoked_count": stats.get("revoked", 0),
        "expired_count": stats.get("expired", 0),
        "demo_mode": bool(current_app.config.get("DEMO_MODE", False)),
    }), 200


@admin_bp.get("/certificates")
@admin_required
def certificates():
    """Return the certificate inventory with optional active/revoked/expired filtering."""
    status_filter = (request.args.get("status") or "").strip().lower()
    if status_filter and status_filter not in _CERTIFICATE_STATUSES:
        return jsonify({"error": "Status must be active, revoked, or expired"}), 400
    rows = get_db().execute(
        """
        SELECT c.id, c.user_id, u.name, u.email, u.public_key,
               c.serial_number, c.issued_at, c.expires_at, c.status, c.certificate
        FROM certificates c
        JOIN users u ON u.id = c.user_id
        ORDER BY c.id DESC
        """
    ).fetchall()
    items = []
    for row in rows:
        effective_status = _certificate_status(row)
        if status_filter and status_filter != effective_status:
            continue
        try:
            fingerprint = public_key_fingerprint(load_public_key(row["public_key"]))
            report = verify_certificate(row["certificate"], expected_email=row["email"])
        except (TypeError, ValueError, OSError):
            fingerprint = None
            report = None
        items.append({
            "id": row["id"],
            "user_id": row["user_id"],
            "name": row["name"],
            "email": row["email"],
            "serial": int(row["serial_number"]),
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "status": effective_status,
            "verification_valid": bool(report and report.valid),
            "fingerprint": fingerprint,
        })
    return jsonify({"certificates": items}), 200


@admin_bp.post("/certificates/<int:serial>/revoke")
@admin_required
def revoke(serial: int):
    """Revoke a certificate and make verification fail immediately."""
    changed = revoke_certificate(serial)
    if not changed:
        return jsonify({"error": "Active certificate not found"}), 404
    log_activity(g.current_user["id"], "admin_certificate_revoke", f"serial={serial}")
    return jsonify({"message": "Certificate revoked", "serial": serial}), 200


@admin_bp.get("/users")
@admin_required
def users():
    """Return a safe account inventory for administrator controls."""
    rows = get_db().execute(
        "SELECT id, name, email, is_admin, is_active, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    return jsonify({"users": [
        {
            "id": row["id"], "name": row["name"], "email": row["email"],
            "is_admin": bool(row["is_admin"]), "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]}), 200


@admin_bp.post("/users/<int:user_id>/toggle-active")
@admin_required
def toggle_user_active(user_id: int):
    """Set an account's active state without permitting self-lockout or loss of all admins."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("is_active"), bool):
        return jsonify({"error": "is_active must be a boolean"}), 400
    active = data["is_active"]
    if user_id == g.current_user["id"] and not active:
        return jsonify({"error": "You cannot deactivate your own administrator account"}), 409

    db = get_db()
    target = db.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if not active and target["is_admin"]:
        admins = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_active = 1").fetchone()[0]
        if admins <= 1:
            return jsonify({"error": "At least one active administrator must remain"}), 409
    if not set_user_active(user_id, active):
        return jsonify({"error": "User not found"}), 404
    log_activity(
        g.current_user["id"],
        "admin_user_status",
        f"target_user_id={user_id} is_active={int(active)}",
    )
    return jsonify({"message": "User active state updated", "is_active": active}), 200


@admin_bp.post("/users/<int:user_id>/certificates/reissue")
@admin_required
def reissue_certificate(user_id: int):
    """Reissue a user's certificate after authenticating the acting administrator."""
    data = request.get_json(silent=True)
    password = data.get("password") if isinstance(data, dict) else None
    if not isinstance(password, str) or not password:
        return jsonify({"error": "Administrator password is required"}), 400
    db = get_db()
    admin_row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.current_user["id"],)).fetchone()
    if admin_row is None or not admin_row["password_hash"] or not check_password_hash(admin_row["password_hash"], password):
        return jsonify({"error": "Administrator password is incorrect"}), 401
    user = db.execute(
        "SELECT id, name, email, public_key FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    if not user["public_key"]:
        return jsonify({"error": "User does not have a public key to certify"}), 409
    try:
        public_key = load_public_key(bytes(user["public_key"]))
        certificate, serial = issue_user_certificate(user["name"], user["email"], public_key)
        cert = x509.load_pem_x509_certificate(certificate)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        current_app.logger.exception("Certificate reissue failed for user_id=%s", user_id)
        return jsonify({"error": f"Certificate could not be reissued: {exc}"}), 503

    db.execute(
        "UPDATE certificates SET status = 'revoked' WHERE user_id = ? AND status = 'active'",
        (user_id,),
    )
    db.execute(
        """
        INSERT INTO certificates (user_id, certificate, serial_number, issued_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        (user_id, certificate, str(serial), cert.not_valid_before_utc.isoformat(),
         cert.not_valid_after_utc.isoformat()),
    )
    db.execute("UPDATE users SET certificate = ? WHERE id = ?", (certificate, user_id))
    db.commit()
    log_activity(g.current_user["id"], "admin_certificate_reissue", f"target_user_id={user_id}")
    return jsonify({"message": "Certificate reissued", "serial": serial}), 201


@admin_bp.get("/activity")
@admin_required
def searchable_activity():
    """Return a bounded, searchable audit log without credential or key material."""
    query = (request.args.get("q") or "").strip()[:100]
    try:
        limit = max(1, min(int(request.args.get("limit", "50")), _MAX_ACTIVITY_LIMIT))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    sql = """
        SELECT a.id, a.user_id, u.name, u.email, a.action, a.detail, a.created_at
        FROM activity_log a LEFT JOIN users u ON u.id = a.user_id
    """
    params: list[Any] = []
    if query:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " WHERE a.action LIKE ? ESCAPE '\\' OR a.detail LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\'"
        params.extend([pattern] * 4)
    rows = get_db().execute(sql + " ORDER BY a.id DESC LIMIT ?", [*params, limit]).fetchall()
    return jsonify({"events": [
        {
            "id": row["id"], "user_id": row["user_id"], "name": row["name"],
            "email": row["email"], "action": row["action"], "detail": row["detail"] or "",
            "created_at": row["created_at"],
        }
        for row in rows
    ]}), 200


@admin_bp.get("/lab/files")
@admin_required
@_demo_mode_required
def lab_files():
    """List safe file metadata available to the local attack simulation lab."""
    rows = get_db().execute(
        """
        SELECT f.id, f.original_filename, f.status, f.created_at,
               s.name AS sender_name, r.name AS receiver_name
        FROM files f JOIN users s ON s.id = f.sender_id JOIN users r ON r.id = f.receiver_id
        ORDER BY f.id DESC LIMIT 100
        """
    ).fetchall()
    return jsonify({"files": [
        {
            "id": row["id"], "original_filename": row["original_filename"],
            "status": row["status"], "created_at": row["created_at"],
            "sender_name": row["sender_name"], "receiver_name": row["receiver_name"],
        }
        for row in rows
    ]}), 200


@admin_bp.post("/lab/tamper-ciphertext")
@admin_required
@_demo_mode_required
def lab_tamper_ciphertext():
    file_id = _requested_lab_file_id()
    if file_id is None:
        return jsonify({"error": "file_id must be a positive integer"}), 400
    return _tamper(file_id, "tamper-ciphertext")


@admin_bp.post("/lab/tamper-metadata")
@admin_required
@_demo_mode_required
def lab_tamper_metadata():
    file_id = _requested_lab_file_id()
    if file_id is None:
        return jsonify({"error": "file_id must be a positive integer"}), 400
    return _tamper(file_id, "tamper-metadata")


@admin_bp.post("/lab/tamper-signature")
@admin_required
@_demo_mode_required
def lab_tamper_signature():
    file_id = _requested_lab_file_id()
    if file_id is None:
        return jsonify({"error": "file_id must be a positive integer"}), 400
    return _tamper(file_id, "tamper-signature")


@admin_bp.post("/lab/swap-cert")
@admin_required
@_demo_mode_required
def lab_swap_certificate():
    file_id = _requested_lab_file_id()
    if file_id is None:
        return jsonify({"error": "file_id must be a positive integer"}), 400
    return _tamper(file_id, "swap-cert")


@admin_bp.post("/lab/restore")
@admin_required
@_demo_mode_required
def lab_restore():
    file_id = _requested_lab_file_id()
    if file_id is None:
        return jsonify({"error": "file_id must be a positive integer"}), 400
    row = _load_lab_file(file_id)
    if row is None:
        return jsonify({"error": "File not found"}), 404
    backup_payload, backup_manifest = _backup_paths(file_id)
    if not backup_payload.is_file() or not backup_manifest.is_file():
        return jsonify({"error": "No demo backup exists for this file"}), 404
    try:
        metadata = json.loads(backup_manifest.read_text(encoding="utf-8"))
        signature = base64.b64decode(metadata["signature"], validate=True)
        certificate = base64.b64decode(metadata["sender_certificate"], validate=True)
        original_filename = metadata["original_filename"]
        if not isinstance(original_filename, str):
            raise ValueError("Invalid backup filename")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        current_app.logger.exception("Demo restore backup is invalid for file_id=%s", file_id)
        return jsonify({"error": "Demo backup is invalid; restore was not applied"}), 409

    payload_path = storage.resolve_storage_path(row["encrypted_filename"])
    _atomic_write(payload_path, backup_payload.read_bytes())
    get_db().execute(
        """
        UPDATE files SET original_filename = ?, signature = ?, sender_certificate = ?, status = 'pending'
        WHERE id = ?
        """,
        (original_filename, signature, certificate, file_id),
    )
    get_db().commit()
    backup_payload.unlink()
    backup_manifest.unlink()
    _audit_demo_action(file_id, "restore")
    return jsonify({"message": "File restored"}), 200
