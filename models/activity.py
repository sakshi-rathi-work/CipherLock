"""Activity logging model for CipherLock security auditing.

Records authentication events (register, login, login_failed, login_locked, logout)
using parameterized SQL into the existing activity_log table.
Private keys, passwords, hashes, session tokens, or raw user-supplied inputs
are NEVER written to activity logs or detail columns.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from database.db import get_db

VALID_ACTIONS = {
    "register",
    "login",
    "login_failed",
    "login_locked",
    "logout",
    # Phase 7 file-sharing events
    "file_upload",
    "file_upload_failed",
    "file_list_sent",
    "file_list_received",
    "file_access_denied",
}


def log_activity(
    user_id: int | None,
    action: str,
    detail: str = "",
    commit: bool = True,
) -> None:
    """Record an audit entry in the activity_log table.

    Args:
        user_id: Integer user ID or None if user unknown / not found.
        action: Standard action verb (register, login, login_failed, login_locked, logout).
        detail: Sanitised short detail (e.g. 'ip=127.0.0.1'). NEVER credentials/secrets.
        commit: Whether to commit immediately on the connection (default True).
    """
    db = get_db()
    db.execute(
        "INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)",
        (user_id, action, detail or ""),
    )
    if commit:
        db.commit()


def log_activity_throttled(
    user_id: int | None,
    action: str,
    detail: str = "",
    window_seconds: int = 60,
    commit: bool = True,
) -> bool:
    """Log an audit entry unless the same user logged ``action`` very recently.

    Used for high-frequency read events (e.g. listing files) so page refreshes do
    not flood the audit trail. Returns True if a row was written.
    """
    db = get_db()
    recent = db.execute(
        """
        SELECT 1 FROM activity_log
        WHERE user_id IS ? AND action = ?
          AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
        LIMIT 1
        """,
        (user_id, action, f"-{int(window_seconds)} seconds"),
    ).fetchone()
    if recent is not None:
        return False
    log_activity(user_id, action, detail, commit=commit)
    return True


def list_recent_activity(user_id: int, limit: int = 10) -> list[dict[str, Any]]:
    """Retrieve the most recent activity log entries for a given user.

    Returns:
        List of dicts with 'action', 'detail', 'created_at'.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT action, detail, created_at
        FROM activity_log
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    return [
        {
            "action": row["action"],
            "detail": row["detail"] or "",
            "created_at": row["created_at"],
        }
        for row in rows
    ]
