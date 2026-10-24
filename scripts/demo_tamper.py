"""Run local-only tampering demonstrations against disposable CipherLock fixtures."""
from __future__ import annotations

from demo_support import demo_environment, send_demo_file


def main() -> int:
    cases = (
        "tamper-ciphertext",
        "tamper-metadata",
        "tamper-signature",
        "swap-cert",
    )
    with demo_environment() as environment:
        users = environment["users"]
        admin = users["admin"]["client"]
        receiver = users["bob"]["client"]
        for action in cases:
            file_id = send_demo_file(users["alice"]["client"], users["bob"]["id"])
            response = admin.post(
                f"/api/admin/lab/{action}",
                json={"file_id": file_id},
            )
            if response.status_code != 200:
                raise RuntimeError(f"{action} was not applied: {response.get_json()}")
            verification = receiver.get(f"/api/files/{file_id}/verify")
            if verification.status_code != 200 or verification.get_json()["report"]["overall"] == "TRUSTED":
                raise RuntimeError(f"{action} did not fail verification.")
            restored = admin.post("/api/admin/lab/restore", json={"file_id": file_id})
            if restored.status_code != 200:
                raise RuntimeError(f"{action} restore failed: {restored.get_json()}")
            verification = receiver.get(f"/api/files/{file_id}/verify")
            if verification.get_json()["report"]["overall"] != "TRUSTED":
                raise RuntimeError(f"{action} restore did not recover trusted status.")
            print(f"PASS {action}: verification blocked; restore returned TRUSTED")
    print(f"PASS — {len(cases)}/{len(cases)} local tamper demonstrations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
