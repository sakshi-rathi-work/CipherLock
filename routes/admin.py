"""Administrator Certificate Authority management endpoints."""
from __future__ import annotations

from flask import Blueprint, jsonify

from crypto.ca import load_ca, revoke_certificate
from crypto.certificates import verify_certificate
from crypto.rsa import load_public_key, public_key_fingerprint
from database.db import get_db
from routes import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/ca-info")
@admin_required
def ca_info():
    """Return non-secret Root CA metadata and certificate statistics."""
    try:
        _, ca_certificate = load_ca()
    except Exception as exc:
        return jsonify({"error": f"Root CA unavailable: {exc}"}), 503

    db = get_db()
    counts = db.execute(
        "SELECT status, COUNT(*) AS count FROM certificates GROUP BY status"
    ).fetchall()
    stats = {row["status"]: row["count"] for row in counts}
    return jsonify({
        "subject": ca_certificate.subject.rfc4514_string(),
        "serial": ca_certificate.serial_number,
        "not_valid_before": ca_certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": ca_certificate.not_valid_after_utc.isoformat(),
        "key_size": ca_certificate.public_key().key_size,
        "certificate_count": sum(stats.values()),
        "active_count": stats.get("active", 0),
        "revoked_count": stats.get("revoked", 0),
    }), 200


@admin_bp.get("/certificates")
@admin_required
def certificates():
    """Return the administrative certificate inventory."""
    db = get_db()
    rows = db.execute(
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
        try:
            fingerprint = public_key_fingerprint(load_public_key(row["public_key"]))
            report = verify_certificate(row["certificate"], expected_email=row["email"])
        except Exception:
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
            "status": row["status"],
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
    return jsonify({"message": "Certificate revoked", "serial": serial}), 200
