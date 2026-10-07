"""Authentication and authorization route decorators for CipherLock API.

Provides:
- login_required: Validates session['user_id'], verifies account is active, attaches to g.current_user.
- admin_required: Requires active session with is_admin=1; returns 403 JSON otherwise.
- current_user: Convenient accessor for g.current_user.
"""
from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import g, jsonify, session

from models.user import get_user_by_id


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Ensure the request is made with an active, authenticated user session."""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        user = get_user_by_id(user_id)
        if user is None or not user["is_active"]:
            session.clear()
            return jsonify({"error": "Authentication required"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Ensure the authenticated user holds administrator privileges."""
    @wraps(f)
    @login_required
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        user = getattr(g, "current_user", None)
        if not user or not user["is_admin"]:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated_function


def current_user() -> Any:
    """Return the currently authenticated user row from Flask's request context g, if any."""
    return getattr(g, "current_user", None)
