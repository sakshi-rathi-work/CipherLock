"""Authentication API blueprint for CipherLock.

Endpoints:
- POST /api/auth/register : Register a new user account with scrypt password hashing.
- POST /api/auth/login    : Authenticate credentials, enforce brute-force lockout, create session.
- POST /api/auth/logout   : Clear session and audit logout.
- GET  /api/auth/me       : Return currently authenticated user profile.
- GET  /api/auth/activity : Return recent authentication activity events for current user.
"""
from __future__ import annotations

import re
from flask import Blueprint, g, jsonify, request, session

from database.db import get_db
from models.activity import list_recent_activity, log_activity
from models.lockout import is_locked, record_failure, reset_key
from models.provisioning import provision_user_crypto
from models.user import (
    DUMMY_PASSWORD_HASH,
    DuplicateEmailError,
    create_user,
    get_user_by_email,
    hash_password,
    public_user_dict,
    validate_password,
    verify_password,
)
from routes import login_required

auth_bp = Blueprint("auth", __name__)

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def _validate_registration_fields(data: dict) -> tuple[dict[str, str], str, str, str]:
    """Validate registration payload and return (field_errors, clean_name, clean_email, password)."""
    field_errors: dict[str, str] = {}

    raw_name = data.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        field_errors["name"] = "Name is required."
    elif len(raw_name.strip()) > 100:
        field_errors["name"] = "Name must not exceed 100 characters."
    elif any(ord(c) < 32 for c in raw_name):
        field_errors["name"] = "Name contains invalid control characters."
    clean_name = raw_name.strip() if isinstance(raw_name, str) else ""

    raw_email = data.get("email")
    clean_email = ""
    if not isinstance(raw_email, str) or not raw_email.strip():
        field_errors["email"] = "Email is required."
    else:
        clean_email = raw_email.strip().lower()
        if len(clean_email) > 254:
            field_errors["email"] = "Email must not exceed 254 characters."
        elif " " in clean_email or clean_email.count("@") != 1:
            field_errors["email"] = "Invalid email format."
        else:
            local_part, domain_part = clean_email.split("@")
            if not local_part or not domain_part or "." not in domain_part:
                field_errors["email"] = "Invalid email format."
            elif not _EMAIL_REGEX.match(clean_email):
                field_errors["email"] = "Invalid email format."

    raw_password = data.get("password")
    if not isinstance(raw_password, str) or not raw_password:
        field_errors["password"] = "Password is required."
    else:
        pw_errors = validate_password(raw_password)
        if pw_errors:
            field_errors["password"] = " ".join(pw_errors)
    clean_password = raw_password if isinstance(raw_password, str) else ""

    return field_errors, clean_name, clean_email, clean_password


@auth_bp.post("/register")
def register():
    """Register a new user account.

    Transactional registration (P11):
    Inserts user, logs activity, invokes cryptographic provisioning placeholder, and commits once.
    On any failure, rolls back cleanly.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Validation failed", "fields": {"_global": "Invalid JSON body"}}), 400

    field_errors, name, email, password = _validate_registration_fields(data)
    if field_errors:
        return jsonify({"error": "Validation failed", "fields": field_errors}), 400

    ip = request.remote_addr or "127.0.0.1"
    pw_hash = hash_password(password)

    db = get_db()
    try:
        # Atomic registration transaction (P11)
        user_id = create_user(name, email, pw_hash, is_admin=False, commit=False)
        log_activity(user_id, "register", f"ip={ip}", commit=False)
        provision_user_crypto(user_id, name, email, password)
        db.commit()
    except DuplicateEmailError:
        db.rollback()
        return jsonify({"error": "An account with this email already exists"}), 409
    except Exception:
        db.rollback()
        return jsonify({"error": "An unexpected error occurred."}), 500

    return jsonify({
        "message": "User registered",
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
        },
    }), 201


@auth_bp.post("/login")
def login():
    """Authenticate user with email and password, enforcing brute-force lockout."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400

    email = data.get("email")
    password = data.get("password")
    if not isinstance(email, str) or not isinstance(password, str) or not email.strip() or not password:
        return jsonify({"error": "Email and password are required."}), 400

    norm_email = email.strip().lower()
    ip = request.remote_addr or "127.0.0.1"

    # 1. Check brute-force lockout (P9)
    locked, retry_after = is_locked(norm_email, ip)
    if locked:
        response = jsonify({
            "error": "Too many failed login attempts. Try again later.",
            "retry_after": retry_after,
        })
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    # 2. Look up user and verify password with timing mitigation (P10)
    user = get_user_by_email(norm_email)
    if user is not None:
        valid_password = verify_password(user["password_hash"], password)
        is_active = bool(user["is_active"])
    else:
        # Timing mitigation: run scrypt verification on dummy hash
        verify_password(DUMMY_PASSWORD_HASH, password)
        valid_password = False
        is_active = False

    # 3. Handle invalid credentials / inactive account identically
    if not valid_password or not is_active:
        is_now_locked, retry_after = record_failure(norm_email, ip)
        user_id = user["id"] if user else None
        log_activity(user_id, "login_failed", f"ip={ip}", commit=True)
        if is_now_locked:
            log_activity(user_id, "login_locked", f"ip={ip}", commit=True)
        return jsonify({"error": "Invalid email or password"}), 401

    # 4. Successful login: reset lockout, regenerate session, record audit
    reset_key(norm_email, ip)
    session.clear()  # Session regeneration (P7)
    session["user_id"] = user["id"]
    session.permanent = True

    log_activity(user["id"], "login", f"ip={ip}", commit=True)

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
        },
    }), 200


@auth_bp.post("/logout")
def logout():
    """Clear authenticated session and audit logout (idempotent)."""
    user_id = session.get("user_id")
    ip = request.remote_addr or "127.0.0.1"
    if user_id:
        log_activity(user_id, "logout", f"ip={ip}", commit=True)
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@auth_bp.get("/me")
@login_required
def me():
    """Return the profile of the currently authenticated user."""
    user = g.current_user
    return jsonify({
        "user": public_user_dict(user, include_admin=True),
    }), 200


@auth_bp.get("/activity")
@login_required
def activity():
    """Return the 10 most recent activity audit entries for the current user (P13)."""
    user = g.current_user
    items = list_recent_activity(user["id"], limit=10)
    return jsonify({"activity": items}), 200
