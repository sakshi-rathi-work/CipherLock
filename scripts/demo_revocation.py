"""Demonstrate that a revoked sender certificate blocks receiver verification."""
from __future__ import annotations

from demo_support import demo_environment, send_demo_file


def main() -> int:
    with demo_environment() as environment:
        users = environment["users"]
        file_id = send_demo_file(users["alice"]["client"], users["bob"]["id"])
        receiver = users["bob"]["client"]
        before = receiver.get(f"/api/files/{file_id}/verify")
        if before.status_code != 200 or before.get_json()["report"]["overall"] != "TRUSTED":
            raise RuntimeError("A newly uploaded local demo file did not verify.")

        with environment["app"].app_context():
            from database.db import get_db
            row = get_db().execute(
                "SELECT serial_number FROM certificates WHERE user_id = ? AND status = 'active'",
                (users["alice"]["id"],),
            ).fetchone()
            serial = int(row["serial_number"])
        revoked = users["admin"]["client"].post(f"/api/admin/certificates/{serial}/revoke")
        if revoked.status_code != 200:
            raise RuntimeError(f"Certificate revocation failed: {revoked.get_json()}")
        after = receiver.get(f"/api/files/{file_id}/verify")
        if after.status_code != 200 or after.get_json()["report"]["overall"] == "TRUSTED":
            raise RuntimeError("Revocation did not make receiver verification fail.")
        print("PASS certificate revocation: receiver verification changed from TRUSTED to rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
