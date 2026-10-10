# Handles secure file uploads, downloads, and sharing operations.
"""Secure upload, storage and sharing API for CipherLock (Phase 7).

Endpoints (all require an authenticated, active session):

- POST /api/files/upload     : encrypt + wrap + sign a file for a recipient, store ciphertext.
- GET  /api/files/sent       : files the current user sent (newest first).
- GET  /api/files/received   : files addressed to the current user (newest first).
- GET  /api/files/stats      : sent/received counters for the dashboard (not audited).
- GET  /api/files/<id>       : metadata for one file, only for its sender or recipient.

There is deliberately no plaintext download or decrypt endpoint: verification,
decryption and download are Phase 8.
"""
from __future__ import annotations

import os
import re
import sqlite3
from typing import Any

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from crypto.certificates import load_certificate, verify_certificate
from crypto.key_storage import PrivateKeyProtectionError, unprotect_private_key
from crypto.package import build_package
from crypto.rsa import KeyFormatError, load_public_key, public_key_fingerprint
from database.db import get_db
from models import file as file_model
from models import storage as file_storage
from models.activity import log_activity, log_activity_throttled
from models.user import get_protected_private_key
from routes import login_required

files_bp = Blueprint("files", __name__, url_prefix="/api/files")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_MAX_FILENAME_LENGTH = 255
_MAX_SEARCH_LENGTH = 100
_SQLITE_MAX_INT = 2**63 - 1

CRYPTO_SUMMARY = {
    "encryption": "AES-256-GCM",
    "key_wrap": "RSA-OAEP (SHA-256, MGF1-SHA-256)",
    "signature": "RSA-PSS (SHA-256, 32-byte salt)",
    "digest": "SHA-256",
}


class _UploadRejected(Exception):
    """Internal control-flow exception carrying a ready-to-send JSON error."""

    def __init__(self, status: int, error: str, reason: str, fields: dict | None = None):
        super().__init__(error)
        self.status = status
        self.error = error
        self.reason = reason
        self.fields = fields


# --------------------------------------------------------------------------- helpers

def _error(status: int, message: str, fields: dict | None = None):
    body: dict[str, Any] = {"error": message}
    if fields:
        body["fields"] = fields
    return jsonify(body), status


def _sanitize_filename(raw: str | None) -> str:
    """Return a safe display filename (``secure_filename`` + length cap)."""
    name = secure_filename(raw or "")
    if not name:
        name = "file"
    if len(name) > _MAX_FILENAME_LENGTH:
        stem, ext = os.path.splitext(name)
        ext = ext[:20]
        name = stem[: _MAX_FILENAME_LENGTH - len(ext)] + ext
    return name


def _find_trusted_identity(user_id: int, email: str, public_key_pem: bytes | None):
    """Return ``(certificate_pem, serial, public_key)`` for a user, or None.

    Both the sender and the recipient go through this check. The identity is
    trusted only if the database holds an *active* certificate that (a) passes the
    full Phase 4 validation (CA signature, validity window, not revoked, subject
    email, KeyUsage) and (b) certifies exactly the public key stored for the user.
    """
    if not public_key_pem:
        return None
    try:
        stored_key = load_public_key(bytes(public_key_pem))
        stored_fingerprint = public_key_fingerprint(stored_key)
    except (KeyFormatError, TypeError, ValueError):
        return None

    rows = get_db().execute(
        "SELECT certificate, serial_number FROM certificates "
        "WHERE user_id = ? AND status = 'active' ORDER BY id DESC",
        (user_id,),
    ).fetchall()
    for row in rows:
        cert_pem = bytes(row["certificate"])
        try:
            report = verify_certificate(cert_pem, expected_email=email)
            if not report.valid:
                continue
            certificate = load_certificate(cert_pem)
            if public_key_fingerprint(certificate.public_key()) != stored_fingerprint:
                continue
        except (TypeError, ValueError):
            continue
        return cert_pem, certificate.serial_number, stored_key
    return None


def _parse_recipient_id(raw: str | None) -> int:
    value = (raw or "").strip()
    if not re.fullmatch(r"[0-9]{1,18}", value):
        raise _UploadRejected(
            400, "Validation failed", "invalid_recipient",
            {"recipient_id": "Select a valid recipient."},
        )
    return int(value)


def _load_recipient(recipient_id: int, sender_id: int):
    """Independently re-validate the chosen recipient from trusted DB records."""
    unavailable = _UploadRejected(
        400, "Validation failed", "recipient_unavailable",
        {"recipient_id": "The selected recipient is not available."},
    )
    if recipient_id == sender_id:
        raise _UploadRejected(
            400, "Validation failed", "self_send",
            {"recipient_id": "You cannot send a file to yourself. Choose another recipient."},
        )
    row = get_db().execute(
        "SELECT id, name, email, public_key, is_active FROM users WHERE id = ?",
        (recipient_id,),
    ).fetchone()
    if row is None or not row["is_active"]:
        raise unavailable  # same response for unknown and inactive accounts
    identity = _find_trusted_identity(row["id"], row["email"], row["public_key"])
    if identity is None:
        raise _UploadRejected(
            400, "Validation failed", "recipient_certificate_invalid",
            {"recipient_id": "The recipient does not have a valid, active certificate."},
        )
    return row, identity[2]


def _load_sender_signing_material(sender):
    """Return ``(private_key, certificate_pem)`` for the authenticated sender."""
    identity = _find_trusted_identity(sender["id"], sender["email"], sender["public_key"])
    if identity is None:
        raise _UploadRejected(
            403, "Your certificate is not valid, so you cannot send files right now.",
            "sender_certificate_invalid",
        )
    cert_pem, _serial, cert_public_key = identity

    protected = get_protected_private_key(sender["id"])
    if protected is None:
        raise _UploadRejected(
            422, "Your signing key is not available. Please contact an administrator.",
            "signing_key_missing",
        )
    try:
        # Phase 3 contract: protected with the app SECRET_KEY + user ID (not the password).
        private_key = unprotect_private_key(
            protected, current_app.config["SECRET_KEY"], sender["id"]
        )
    except (PrivateKeyProtectionError, TypeError, ValueError):
        current_app.logger.error("Could not unlock signing key for user_id=%s", sender["id"])
        raise _UploadRejected(
            500, "Your signing key could not be unlocked. Please contact an administrator.",
            "signing_key_unlock_failed",
        ) from None
    if private_key.public_key().public_numbers() != cert_public_key.public_numbers():
        raise _UploadRejected(
            422, "Your signing key does not match your certificate. Please contact an administrator.",
            "signing_key_mismatch",
        )
    return private_key, cert_pem


def _read_upload(max_bytes: int) -> tuple[bytes, str]:
    """Validate the multipart request and return ``(plaintext, display_filename)``."""
    parts = request.files.getlist("file")
    if len(parts) != 1:
        message = "Select a file to send." if not parts else "Upload exactly one file per request."
        raise _UploadRejected(400, "Validation failed", "file_missing", {"file": message})
    part = parts[0]
    if not part.filename or not part.filename.strip():
        raise _UploadRejected(
            400, "Validation failed", "file_missing", {"file": "Select a file to send."}
        )
    data = part.stream.read(max_bytes + 1)  # in memory only (see InMemoryUploadRequest)
    if len(data) > max_bytes:
        mib = max_bytes // (1024 * 1024)
        raise _UploadRejected(
            413, f"File is too large. The maximum size is {mib} MiB.", "file_too_large"
        )
    if len(data) == 0:
        raise _UploadRejected(
            400, "Validation failed", "file_empty", {"file": "Empty files cannot be sent."}
        )
    return data, _sanitize_filename(part.filename)


def _crypto_summary(file_data: dict) -> dict:
    return {**CRYPTO_SUMMARY, "ciphertext_sha256": file_data.get("ciphertext_sha256")}


def _upload_response(row, *, duplicate: bool):
    file_data = file_model.file_to_dict(row, include_digest=True)
    file_data["crypto"] = _crypto_summary(file_data)
    body = {
        "message": "File already sent." if duplicate else "File encrypted, signed and sent securely.",
        "duplicate": duplicate,
        "file": file_data,
    }
    return jsonify(body), (200 if duplicate else 201)


def _log_failure(user_id: int, reason: str) -> None:
    try:
        log_activity(user_id, "file_upload_failed", f"reason={reason}", commit=True)
    except sqlite3.Error:  # auditing must never mask the original error
        current_app.logger.exception("Could not write upload-failure audit entry")


# ---------------------------------------------------------------------------- upload

@files_bp.post("/upload")
@login_required
def upload():
    """Encrypt, sign and store a file for one recipient (HTTP 201 on success)."""
    sender = g.current_user  # identity comes ONLY from the authenticated session
    db = get_db()
    stored_name: str | None = None
    try:
        if not request.mimetype or request.mimetype != "multipart/form-data":
            raise _UploadRejected(400, "Request must be multipart/form-data.", "not_multipart")

        recipient_id = _parse_recipient_id(request.form.get("recipient_id"))
        request_id = (request.form.get("client_request_id") or "").strip() or None
        if request_id is not None and not _REQUEST_ID_RE.fullmatch(request_id):
            raise _UploadRejected(
                400, "Validation failed", "invalid_request_id",
                {"client_request_id": "Invalid request identifier."},
            )

        # Idempotent retry: the same sender + key never produces a second record.
        if request_id:
            existing = file_model.get_file_by_request_id(sender["id"], request_id)
            if existing is not None:
                if existing["receiver_id"] != recipient_id:
                    raise _UploadRejected(
                        409, "This request identifier was already used for a different transfer.",
                        "request_id_conflict",
                    )
                return _upload_response(existing, duplicate=True)

        max_bytes = int(current_app.config.get("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))
        plaintext, display_name = _read_upload(max_bytes)
        recipient, recipient_public_key = _load_recipient(recipient_id, sender["id"])
        sender_key, sender_cert_pem = _load_sender_signing_material(sender)

        # Phase 6 hybrid pipeline: fresh AES-256-GCM key + nonce, RSA-OAEP wrap,
        # RSA-PSS signature over the canonical header. Nothing is re-implemented here.
        try:
            package = build_package(
                plaintext, display_name, sender["id"], recipient["id"],
                sender_key, sender_cert_pem, recipient_public_key,
            )
        except (TypeError, ValueError):
            current_app.logger.exception("Package construction failed")
            raise _UploadRejected(
                500, "The file could not be encrypted. Please try again.", "encryption_failed"
            ) from None
        finally:
            del plaintext, sender_key

        # Persist: ciphertext first (atomic write), then the DB row; clean up on failure.
        stored_name = file_storage.new_storage_name()
        try:
            file_storage.write_ciphertext(stored_name, package["ciphertext_with_tag"])
        except (OSError, file_storage.StorageError):
            current_app.logger.exception("Could not write encrypted payload")
            stored_name = None  # write_ciphertext cleans up its own temp file
            raise _UploadRejected(
                500, "The file could not be stored. Please try again.", "storage_write_failed"
            ) from None

        file_id = file_model.create_file_record(
            sender_id=sender["id"],
            receiver_id=recipient["id"],
            original_filename=display_name,
            encrypted_filename=stored_name,
            package=package,
            client_request_id=request_id,
            commit=False,
        )
        log_activity(
            sender["id"], "file_upload",
            f"file_id={file_id} recipient_id={recipient['id']}", commit=False,
        )
        db.commit()
        stored_name = None  # committed: the payload now belongs to a real record; never clean it up
        row = file_model.get_file_for_sender(file_id, sender["id"])
        return _upload_response(row, duplicate=False)

    except _UploadRejected as rejected:
        db.rollback()
        if stored_name:
            file_storage.delete_ciphertext(stored_name)
        _log_failure(sender["id"], rejected.reason)
        return _error(rejected.status, rejected.error, rejected.fields)

    except sqlite3.IntegrityError:
        db.rollback()
        if stored_name:
            file_storage.delete_ciphertext(stored_name)
        # Lost a race with an identical retry: return the winner instead of an error.
        request_id = (request.form.get("client_request_id") or "").strip()
        if request_id:
            existing = file_model.get_file_by_request_id(sender["id"], request_id)
            if existing is not None and existing["receiver_id"] == int(request.form["recipient_id"]):
                return _upload_response(existing, duplicate=True)
        current_app.logger.exception("Could not record uploaded file")
        _log_failure(sender["id"], "database_error")
        return _error(500, "The file could not be saved. Please try again.")

    except HTTPException:
        # e.g. 413 from MAX_CONTENT_LENGTH: let the app-level JSON handler answer.
        db.rollback()
        if stored_name:
            file_storage.delete_ciphertext(stored_name)
        raise

    except Exception:
        db.rollback()
        if stored_name:
            file_storage.delete_ciphertext(stored_name)
        current_app.logger.exception("Unexpected upload failure")
        _log_failure(sender["id"], "unexpected_error")
        return _error(500, "The file could not be saved. Please try again.")


# --------------------------------------------------------------------------- listing

def _page_params() -> tuple[str | None, int, int]:
    try:
        limit = int(request.args.get("limit", file_model.DEFAULT_PAGE_SIZE))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        raise _UploadRejected(400, "limit and offset must be integers.", "bad_paging") from None
    if limit < 1 or offset < 0 or offset > _SQLITE_MAX_INT:
        raise _UploadRejected(400, "Invalid paging parameters.", "bad_paging")
    query = (request.args.get("q") or "").strip()[:_MAX_SEARCH_LENGTH] or None
    return query, min(limit, file_model.MAX_PAGE_SIZE), offset


def _listing(direction: str):
    user = g.current_user
    try:
        query, limit, offset = _page_params()
    except _UploadRejected as bad:
        return _error(bad.status, bad.error)
    fetch = file_model.list_sent if direction == "sent" else file_model.list_received
    rows, total = fetch(user["id"], query=query, limit=limit, offset=offset)
    log_activity_throttled(user["id"], f"file_list_{direction}", f"count={total}")
    return jsonify({
        "files": [file_model.file_to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }), 200


@files_bp.get("/sent")
@login_required
def sent_files():
    """Files sent by the authenticated user, newest first."""
    return _listing("sent")


@files_bp.get("/received")
@login_required
def received_files():
    """Files addressed to the authenticated user, newest first."""
    return _listing("received")


@files_bp.get("/stats")
@login_required
def file_stats():
    """Counters for the dashboard (read-only, not written to the audit log)."""
    uid = g.current_user["id"]
    return jsonify({
        "sent_count": file_model.count_sent(uid),
        "received_count": file_model.count_received(uid),
    }), 200


# ---------------------------------------------------------------------------- detail

@files_bp.get("/<int:file_id>")
@login_required
def file_detail(file_id: int):
    """Safe metadata for one file; 404 for missing *and* unauthorized IDs alike."""
    user = g.current_user
    row = None
    if 0 < file_id <= _SQLITE_MAX_INT:
        row = file_model.get_file_for_participant(file_id, user["id"])
    if row is None:
        log_activity(user["id"], "file_access_denied", f"file_id={file_id}", commit=True)
        return _error(404, "File not found")
    data = file_model.file_to_dict(row, include_digest=True, include_storage_status=True)
    data["crypto"] = _crypto_summary(data)
    return jsonify({"file": data}), 200
