"""Phase 10 – KMS administration API routes.

All endpoints require admin privileges. The KMS routes manage the
envelope-encryption key hierarchy: KEK versioning, DEK management,
rotation policies, compromise/recovery workflows, and audit logging.

Blueprint prefix: ``/api/kms``
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, g, jsonify, request

from routes import admin_required, login_required

kms_bp = Blueprint("kms", __name__, url_prefix="/api/kms")


def _error(status: int, message: str, fields: dict | None = None):
    body: dict[str, Any] = {"error": message}
    if fields:
        body["fields"] = fields
    return jsonify(body), status


def _json_body() -> dict[str, Any]:
    """Return the parsed JSON body or an empty dict."""
    if request.is_json and request.json:
        return request.json
    return {}


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@kms_bp.get("/status")
@admin_required
def kms_status():
    """Return comprehensive KMS status including active KEK, rotation info."""
    from models.kms import get_kms_status
    try:
        status = get_kms_status()
        return jsonify({"kms": status}), 200
    except Exception as exc:
        current_app.logger.exception("KMS status check failed")
        return _error(500, f"KMS status unavailable: {exc}")


# ---------------------------------------------------------------------------
# KEK management
# ---------------------------------------------------------------------------

@kms_bp.get("/keys")
@admin_required
def list_keys():
    """List all KEK versions with metadata (no key material)."""
    from models.kms import list_kek_versions
    versions = list_kek_versions()
    return jsonify({"keys": versions, "total": len(versions)}), 200


@kms_bp.post("/keys")
@admin_required
def create_key():
    """Create a new KEK (demoting the current active one)."""
    from models.kms import create_kek
    body = _json_body()
    try:
        result = create_kek(
            user_id=g.current_user["id"],
            description=body.get("description", "Manual creation"),
        )
        return jsonify({"message": "KEK created successfully.", "key": result}), 201
    except Exception as exc:
        current_app.logger.exception("KEK creation failed")
        return _error(500, f"Could not create KEK: {exc}")


@kms_bp.get("/keys/<int:version>")
@admin_required
def get_key(version: int):
    """Get metadata for a specific KEK version."""
    from models.kms import get_kek_by_version, KEKNotFoundError, KMSError
    try:
        _, meta = get_kek_by_version(version)
        return jsonify({"key": meta}), 200
    except KEKNotFoundError:
        return _error(404, f"KEK version {version} not found.")
    except KMSError as exc:
        return _error(400, str(exc))


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

@kms_bp.post("/rotate")
@admin_required
def rotate():
    """Trigger KEK rotation. Creates a new active KEK."""
    from models.kms import rotate_kek
    body = _json_body()
    try:
        result = rotate_kek(
            user_id=g.current_user["id"],
            description=body.get("description", "Admin-triggered rotation"),
        )
        return jsonify({
            "message": f"KEK rotated to version {result['version']}.",
            "key": result,
        }), 201
    except Exception as exc:
        current_app.logger.exception("KEK rotation failed")
        return _error(500, f"Rotation failed: {exc}")


@kms_bp.get("/rotation-check")
@admin_required
def rotation_check():
    """Check if rotation is needed based on policy."""
    from models.kms import check_rotation_needed
    result = check_rotation_needed()
    return jsonify({"rotation_check": result}), 200


# ---------------------------------------------------------------------------
# Rewrapping
# ---------------------------------------------------------------------------

@kms_bp.post("/rewrap")
@admin_required
def rewrap():
    """Rewrap all DEKs under the active (or specified) KEK."""
    from models.kms import rewrap_all_deks, NoActiveKEKError
    body = _json_body()
    target_version = body.get("target_kek_version")
    try:
        result = rewrap_all_deks(
            target_kek_version=target_version,
            user_id=g.current_user["id"],
        )
        return jsonify({
            "message": f"Rewrap complete: {result['rewrapped']}/{result['total']} DEKs rewrapped.",
            "result": result,
        }), 200
    except NoActiveKEKError:
        return _error(400, "No active KEK. Create one before rewrapping.")
    except Exception as exc:
        current_app.logger.exception("DEK rewrap failed")
        return _error(500, f"Rewrap failed: {exc}")


# ---------------------------------------------------------------------------
# Compromise & recovery
# ---------------------------------------------------------------------------

@kms_bp.post("/keys/<int:version>/compromise")
@admin_required
def compromise_key(version: int):
    """Mark a KEK version as compromised."""
    from models.kms import compromise_kek, KEKNotFoundError, KMSError
    body = _json_body()
    try:
        result = compromise_kek(
            version=version,
            user_id=g.current_user["id"],
            reason=body.get("reason", ""),
        )
        return jsonify({
            "message": f"KEK v{version} marked as compromised.",
            "key": result,
        }), 200
    except KEKNotFoundError:
        return _error(404, f"KEK version {version} not found.")
    except KMSError as exc:
        return _error(400, str(exc))


@kms_bp.post("/keys/<int:version>/recover")
@admin_required
def recover_key(version: int):
    """Recover a compromised KEK (after remediation)."""
    from models.kms import recover_from_compromise, KEKNotFoundError, KMSError
    try:
        result = recover_from_compromise(
            version=version,
            user_id=g.current_user["id"],
        )
        return jsonify({
            "message": f"KEK v{version} recovered.",
            "key": result,
        }), 200
    except KEKNotFoundError:
        return _error(404, f"KEK version {version} not found.")
    except KMSError as exc:
        return _error(400, str(exc))


@kms_bp.post("/keys/<int:version>/destroy")
@admin_required
def destroy_key(version: int):
    """Permanently destroy a KEK version (irreversible)."""
    from models.kms import destroy_kek, KEKNotFoundError, KMSError
    try:
        result = destroy_kek(
            version=version,
            user_id=g.current_user["id"],
        )
        return jsonify({
            "message": f"KEK v{version} permanently destroyed.",
            "key": result,
        }), 200
    except KEKNotFoundError:
        return _error(404, f"KEK version {version} not found.")
    except KMSError as exc:
        return _error(400, str(exc))


# ---------------------------------------------------------------------------
# Rotation policy
# ---------------------------------------------------------------------------

@kms_bp.get("/policy")
@admin_required
def get_policy():
    """Return the current rotation policy."""
    from models.kms import get_rotation_policy
    return jsonify({"policy": get_rotation_policy()}), 200


@kms_bp.put("/policy")
@admin_required
def update_policy():
    """Update the rotation policy."""
    from models.kms import update_rotation_policy, PolicyViolationError
    body = _json_body()
    try:
        result = update_rotation_policy(
            rotation_interval_days=body.get("rotation_interval_days"),
            auto_rotate=body.get("auto_rotate"),
            max_versions=body.get("max_versions"),
            user_id=g.current_user["id"],
        )
        return jsonify({"message": "Policy updated.", "policy": result}), 200
    except PolicyViolationError as exc:
        return _error(400, str(exc))


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@kms_bp.get("/audit")
@admin_required
def audit_log():
    """Return KMS audit log entries."""
    from models.kms import list_kms_audit
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return _error(400, "limit and offset must be integers.")

    action_filter = request.args.get("action")
    entries, total = list_kms_audit(
        limit=min(limit, 200),
        offset=max(offset, 0),
        action_filter=action_filter,
    )
    return jsonify({"entries": entries, "total": total, "limit": limit, "offset": offset}), 200


# ---------------------------------------------------------------------------
# DEK info (for file detail inspection)
# ---------------------------------------------------------------------------

@kms_bp.get("/dek/<int:file_id>")
@admin_required
def dek_info(file_id: int):
    """Return DEK metadata for a file (no key material)."""
    from models.kms import get_dek_info
    info = get_dek_info(file_id)
    if info is None:
        return _error(404, f"No DEK registered for file {file_id}.")
    return jsonify({"dek": info}), 200


# ---------------------------------------------------------------------------
# KMS initialization endpoint
# ---------------------------------------------------------------------------

@kms_bp.post("/initialize")
@admin_required
def initialize():
    """Ensure the KMS is initialized with an active KEK."""
    from models.kms import ensure_kms_initialized
    try:
        result = ensure_kms_initialized()
        return jsonify({
            "message": "KMS initialized." if result["status"] == "initialized"
                       else "KMS already initialized.",
            "result": result,
        }), 200
    except Exception as exc:
        current_app.logger.exception("KMS initialization failed")
        return _error(500, f"KMS initialization failed: {exc}")
