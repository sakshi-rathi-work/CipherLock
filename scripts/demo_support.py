"""Disposable local fixtures shared by the Phase 9 command-line demonstrations."""
from __future__ import annotations

import io
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app

PASSWORD = "DemoPassword9Safe"


@contextmanager
def demo_environment() -> Iterator[dict]:
    """Create a fully isolated temporary app, CA, database, and demo users."""
    with tempfile.TemporaryDirectory(prefix="cipherlock-phase9-") as directory:
        base = Path(directory)
        app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "DEMO_MODE": True,
            "SECRET_KEY": "phase-nine-disposable-test-secret",
            "CIPHERLOCK_CA_PASSPHRASE": "phase-nine-disposable-ca-passphrase",
            "DATABASE_PATH": base / "database" / "cipherlock.db",
            "STORAGE_DIR": base / "storage",
            "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
            "CERTIFICATES_DIR": base / "certificates",
            "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
            "USER_CERTIFICATES_DIR": base / "certificates" / "users",
            "KEYS_DIR": base / "keys",
            "CA_KEYS_DIR": base / "keys" / "ca",
            "USER_KEYS_DIR": base / "keys" / "users",
        })
        users = {}
        for name in ("Alice", "Bob", "Mallory", "Admin"):
            email = f"{name.lower()}@example.test"
            client = app.test_client()
            response = client.post(
                "/api/auth/register",
                json={"name": name, "email": email, "password": PASSWORD},
            )
            if response.status_code != 201:
                raise RuntimeError(f"Demo user registration failed: {response.get_json()}")
            user_id = response.get_json()["user"]["id"]
            response = client.post(
                "/api/auth/login", json={"email": email, "password": PASSWORD}
            )
            if response.status_code != 200:
                raise RuntimeError("Demo user login failed.")
            users[name.lower()] = {"id": user_id, "email": email, "client": client}
        with app.app_context():
            connection = sqlite3.connect(app.config["DATABASE_PATH"])
            try:
                connection.execute(
                    "UPDATE users SET is_admin = 1 WHERE id = ?",
                    (users["admin"]["id"],),
                )
                connection.commit()
            finally:
                connection.close()
        yield {"app": app, "base": base, "users": users}


def send_demo_file(sender, recipient_id: int, content: bytes = b"local demo only") -> int:
    """Upload one harmless in-memory fixture file and return its record ID."""
    response = sender.post(
        "/api/files/upload",
        data={
            "file": (io.BytesIO(content), "phase9-demo.txt"),
            "recipient_id": str(recipient_id),
        },
        content_type="multipart/form-data",
    )
    if response.status_code != 201:
        raise RuntimeError(f"Demo file upload failed: {response.get_json()}")
    return response.get_json()["file"]["id"]
