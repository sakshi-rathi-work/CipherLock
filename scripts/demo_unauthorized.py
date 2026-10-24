"""Verify seven access-control boundaries using a disposable local app."""
from __future__ import annotations

import sqlite3

from demo_support import demo_environment, send_demo_file


def main() -> int:
    with demo_environment() as environment:
        app, users = environment["app"], environment["users"]
        alice = users["alice"]
        bob = users["bob"]
        mallory = users["mallory"]
        admin = users["admin"]
        file_id = send_demo_file(alice["client"], bob["id"])
        guest = app.test_client()

        checks = [
            ("anonymous received list", guest.get("/api/files/received").status_code, 401),
            ("non-recipient verification", mallory["client"].get(f"/api/files/{file_id}/verify").status_code, 404),
            ("non-recipient download", mallory["client"].post(f"/api/files/{file_id}/download", json={"password": "DemoPassword9Safe"}).status_code, 404),
            ("regular user admin inventory", alice["client"].get("/api/admin/ca-info").status_code, 403),
            ("regular user attack lab", alice["client"].post("/api/admin/lab/tamper-ciphertext", json={"file_id": file_id}).status_code, 403),
        ]
        with app.app_context():
            connection = sqlite3.connect(app.config["DATABASE_PATH"])
            try:
                connection.execute("UPDATE users SET is_active = 0 WHERE id = ?", (mallory["id"],))
                connection.commit()
            finally:
                connection.close()
        checks.append((
            "disabled account login",
            guest.post("/api/auth/login", json={"email": mallory["email"], "password": "DemoPassword9Safe"}).status_code,
            401,
        ))
        app.config["DEMO_MODE"] = False
        checks.append((
            "disabled demo mode",
            admin["client"].post("/api/admin/lab/tamper-ciphertext", json={"file_id": file_id}).status_code,
            404,
        ))
        for label, actual, expected in checks:
            if actual != expected:
                raise RuntimeError(f"{label}: expected HTTP {expected}, received {actual}")
            print(f"PASS {label}: HTTP {actual}")
    print(f"PASS — {len(checks)}/{len(checks)} local authorization demonstrations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
