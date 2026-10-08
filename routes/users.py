"""Authenticated public certificate directory endpoints."""
from __future__ import annotations

from flask import Blueprint, jsonify

from crypto.certificates import load_certificate, verify_certificate
from crypto.rsa import load_public_key, public_key_fingerprint
from database.db import get_db
from routes import login_required

users_bp = Blueprint("users", __name__, url_prefix="/api/users")


@users_bp.get("/directory")
@login_required
def directory():
    """List active users and their certificate trust metadata."""
    db = get_db()
    rows = db.execute(
        """
        SELECT u.id, u.name, u.email, u.public_key, c.certificate,
               c.serial_number, c.status, c.expires_at
        FROM users u
        JOIN certificates c ON c.user_id = u.id
        WHERE u.is_active = 1 AND c.status = 'active'
        ORDER BY u.name COLLATE NOCASE ASC
        """
    ).fetchall()

    result = []
    for row in rows:
        try:
            public_key = load_public_key(row["public_key"])
            fingerprint = public_key_fingerprint(public_key)
            report = verify_certificate(row["certificate"], expected_email=row["email"])
        except Exception:
            fingerprint = None
            report = None
        result.append({
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "cert_serial": int(row["serial_number"]),
            "fingerprint": fingerprint,
            "status": "active" if report and report.valid else "invalid",
            "expires_at": row["expires_at"],
        })
    return jsonify({"users": result}), 200


@users_bp.get("/<int:user_id>/certificate")
@login_required
def certificate(user_id: int):
    """Return a user's certificate in PEM plus a structured trust report."""
    db = get_db()
    row = db.execute(
        """
        SELECT u.id, u.name, u.email, u.is_active, c.certificate, c.serial_number, c.status
        FROM users u
        LEFT JOIN certificates c ON c.user_id = u.id
        WHERE u.id = ?
        ORDER BY c.id DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if row is None or row["certificate"] is None:
        return jsonify({"error": "Certificate not found"}), 404

    report = verify_certificate(row["certificate"], expected_email=row["email"])
    cert = load_certificate(row["certificate"])
    return jsonify({
        "certificate_pem": row["certificate"].decode("ascii"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "status": row["status"],
        "verification": {
            "ca_signature_ok": report.ca_signature_ok,
            "validity_ok": report.validity_ok,
            "not_revoked": report.not_revoked,
            "subject_ok": report.subject_ok,
            "key_usage_ok": report.key_usage_ok,
            "valid": report.valid,
            "reason": report.reason,
        },
    }), 200
