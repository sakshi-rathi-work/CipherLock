"""User model and authentication primitives for CipherLock.

Security guarantees:
- Passwords are strictly hashed with Werkzeug's scrypt implementation (method="scrypt").
- Password policy enforced: >=10 chars, <=128 chars, >=1 uppercase, >=1 lowercase, >=1 digit.
- Sensitive columns (password_hash, encrypted_private_key) are NEVER exposed via get_user_by_id
  or public serializers.
- SQL injection prevention: 100% parameterized queries.
- Duplicate email checks handle race conditions via SQLite IntegrityError -> DuplicateEmailError.
- Timing attack mitigation: dummy scrypt hash verification for unknown email lookups.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from database.db import get_db

# Dummy hash for timing attack mitigation on unknown user lookups (P10)
# Uses standard scrypt cost so response timing cannot distinguish existing from non-existing accounts.
DUMMY_PASSWORD_HASH = generate_password_hash("CipherLockTimingMitigationDummyPass123!", method="scrypt")


class DuplicateEmailError(Exception):
    """Raised when attempting to create a user with an already registered email."""


def validate_password(password: str) -> list[str]:
    """Validate password against CipherLock security policy.

    Rules:
    - Minimum length: 10 characters
    - Maximum length: 128 characters (DoS mitigation against heavy scrypt hashing)
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 numeric digit

    Returns:
        List of error messages describing unmet criteria (empty list if valid).
    """
    errors: list[str] = []
    if len(password) < 10:
        errors.append("Password must be at least 10 characters long.")
    if len(password) > 128:
        errors.append("Password must not exceed 128 characters.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")
    return errors


def hash_password(password: str) -> str:
    """Hash a plaintext password using Werkzeug's salted scrypt algorithm."""
    hashed = generate_password_hash(password, method="scrypt")
    if not hashed.startswith("scrypt:"):
        raise ValueError("Password hash did not produce scrypt digest.")
    return hashed


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a plaintext password against a stored scrypt hash."""
    return check_password_hash(password_hash, password)


def create_user(
    name: str,
    email: str,
    password_hash: str,
    is_admin: bool = False,
    commit: bool = True,
) -> int:
    """Create a new user row in the database.

    Args:
        name: Sanitised full name.
        email: Lowercased, stripped email.
        password_hash: scrypt hash string.
        is_admin: Admin flag (default False).
        commit: Whether to commit immediately (default True; set False for multi-step transactions).

    Returns:
        The newly created user's integer id.

    Raises:
        DuplicateEmailError: If the email already exists.
    """
    db = get_db()
    norm_email = email.strip().lower()
    norm_name = name.strip()
    try:
        cursor = db.execute(
            """
            INSERT INTO users (name, email, password_hash, is_admin, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (norm_name, norm_email, password_hash, 1 if is_admin else 0),
        )
        if commit:
            db.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError as e:
        if commit:
            db.rollback()
        if "UNIQUE" in str(e).upper() or "users.email" in str(e).lower():
            raise DuplicateEmailError("An account with this email already exists") from e
        raise


def get_user_by_email(email: str) -> sqlite3.Row | None:
    """Look up a user by email, returning the full row including password_hash.

    INTERNAL SERVER USE ONLY (e.g. login authentication). Never return this row to API clients.
    """
    db = get_db()
    norm_email = email.strip().lower()
    return db.execute(
        "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
        (norm_email,),
    ).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    """Look up a user by ID, selecting SAFE columns only.

    NEVER selects password_hash or encrypted_private_key.
    """
    db = get_db()
    return db.execute(
        """
        SELECT id, name, email, public_key, certificate, is_admin, is_active, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def list_other_users(current_user_id: int) -> list[sqlite3.Row]:
    """Return active users other than current_user_id, with safe columns only (id, name, email)."""
    db = get_db()
    return db.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE id != ? AND is_active = 1
        ORDER BY name ASC
        """,
        (current_user_id,),
    ).fetchall()


def set_user_active(user_id: int, active: bool, commit: bool = True) -> bool:
    """Activate or deactivate a user account. Returns True if a row was updated."""
    db = get_db()
    cursor = db.execute(
        "UPDATE users SET is_active = ? WHERE id = ?",
        (1 if active else 0, user_id),
    )
    if commit:
        db.commit()
    return cursor.rowcount > 0


def public_user_dict(row: sqlite3.Row | dict[str, Any], include_admin: bool = False) -> dict[str, Any]:
    """Serialize a user row into a safe, client-facing dictionary.

    Guarantees no sensitive columns (password, password_hash, private_key) leak.
    """
    data = {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
    }
    if include_admin:
        data["is_admin"] = bool(row["is_admin"])
    return data
