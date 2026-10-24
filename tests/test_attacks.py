"""Phase 9 local attack-lab, admin-control, and audit coverage."""
from __future__ import annotations

import io
import sqlite3

import pytest

from app import create_app

PASSWORD = "CorrectHorse9Battery"
ADMIN_PASSWORD = "AdminPassword9Strong"


@pytest.fixture
def phase9(tmp_path):
    base = tmp_path
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DEMO_MODE": True,
        "SECRET_KEY": "phase-nine-test-secret-key-32-bytes",
        "CIPHERLOCK_CA_PASSPHRASE": "phase-nine-test-ca-passphrase",
        "DATABASE_PATH": base / "phase9.db",
        "STORAGE_DIR": base / "storage",
        "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
        "CERTIFICATES_DIR": base / "certificates",
        "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": base / "certificates" / "users",
        "KEYS_DIR": base / "keys",
        "CA_KEYS_DIR": base / "keys" / "ca",
        "USER_KEYS_DIR": base / "keys" / "users",
    })
    clients = {}
    users = {}
    for name, password in (
        ("alice", PASSWORD),
        ("bob", PASSWORD),
        ("outsider", PASSWORD),
        ("admin", ADMIN_PASSWORD),
    ):
        client = app.test_client()
        email = f"{name}@phase9.test"
        response = client.post(
            "/api/auth/register",
            json={"name": name.title(), "email": email, "password": password},
        )
        assert response.status_code == 201
        user_id = response.get_json()["user"]["id"]
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200
        clients[name] = client
        users[name] = {"id": user_id, "email": email, "password": password}
    with sqlite3.connect(app.config["DATABASE_PATH"]) as connection:
        connection.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (users["admin"]["id"],))
    return {"app": app, "clients": clients, "users": users}


def upload(phase9, sender="alice", receiver="bob"):
    response = phase9["clients"][sender].post(
        "/api/files/upload",
        data={
            "file": (io.BytesIO(b"phase nine reversible local attack demo"), "demo.txt"),
            "recipient_id": str(phase9["users"][receiver]["id"]),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["file"]["id"]


@pytest.mark.parametrize("attack", [
    "tamper-ciphertext",
    "tamper-metadata",
    "tamper-signature",
    "swap-cert",
])
def test_lab_attacks_fail_verification_and_restore_trusted_package(phase9, attack):
    file_id = upload(phase9)
    admin = phase9["clients"]["admin"]
    receiver = phase9["clients"]["bob"]

    response = admin.post(f"/api/admin/lab/{attack}", json={"file_id": file_id})
    assert response.status_code == 200, response.get_json()
    report = receiver.get(f"/api/files/{file_id}/verify").get_json()["report"]
    assert report["overall"] != "TRUSTED"
    denied = receiver.post(
        f"/api/files/{file_id}/download", json={"password": PASSWORD}
    )
    assert denied.status_code == 400
    assert "Signature verification failed" in denied.get_json()["error"]

    restored = admin.post("/api/admin/lab/restore", json={"file_id": file_id})
    assert restored.status_code == 200
    report = receiver.get(f"/api/files/{file_id}/verify").get_json()["report"]
    assert report["overall"] == "TRUSTED"


def test_ciphertext_tampering_blocks_download_and_is_audited(phase9):
    file_id = upload(phase9)
    admin = phase9["clients"]["admin"]
    receiver = phase9["clients"]["bob"]
    assert admin.post(
        "/api/admin/lab/tamper-ciphertext", json={"file_id": file_id}
    ).status_code == 200

    response = receiver.post(
        f"/api/files/{file_id}/download", json={"password": PASSWORD}
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "Signature verification failed. File may have been modified or sender authenticity could not be established."
    )
    events = admin.get("/api/admin/activity", query_string={"q": "SIMULATED ATTACK"}).get_json()["events"]
    assert any(f"file_id={file_id}" in event["detail"] for event in events)
    assert "password_hash" not in str(events)
    assert admin.post("/api/admin/lab/restore", json={"file_id": file_id}).status_code == 200


def test_lab_requires_admin_and_demo_mode(phase9):
    file_id = upload(phase9)
    path = "/api/admin/lab/tamper-ciphertext"
    body = {"file_id": file_id}
    assert phase9["clients"]["alice"].post(path, json=body).status_code == 403
    assert phase9["app"].test_client().post(path, json=body).status_code == 401
    phase9["app"].config["DEMO_MODE"] = False
    assert phase9["clients"]["admin"].post(path, json=body).status_code == 404
    assert phase9["clients"]["admin"].get("/api/admin/lab/files").status_code == 404


def test_lab_validates_file_ids_and_requires_restore_backup(phase9):
    admin = phase9["clients"]["admin"]
    assert admin.post("/api/admin/lab/tamper-ciphertext", json={"file_id": -1}).status_code == 400
    assert admin.post("/api/admin/lab/tamper-ciphertext", json={"file_id": True}).status_code == 400
    assert admin.post("/api/admin/lab/restore", json={"file_id": 999}).status_code == 404
    assert admin.post("/api/admin/lab/tamper-ciphertext", json={"file_id": 999}).status_code == 404


def test_admin_account_controls_and_last_admin_guard(phase9):
    admin = phase9["clients"]["admin"]
    bob_id = phase9["users"]["bob"]["id"]
    response = admin.post(
        f"/api/admin/users/{bob_id}/toggle-active", json={"is_active": False}
    )
    assert response.status_code == 200
    blocked_login = phase9["app"].test_client().post(
        "/api/auth/login",
        json={"email": phase9["users"]["bob"]["email"], "password": PASSWORD},
    )
    assert blocked_login.status_code == 401
    assert admin.post(
        f"/api/admin/users/{phase9['users']['admin']['id']}/toggle-active",
        json={"is_active": False},
    ).status_code == 409
    assert admin.post(
        f"/api/admin/users/{bob_id}/toggle-active", json={"is_active": "false"}
    ).status_code == 400
    inventory = admin.get("/api/admin/users").get_json()["users"]
    assert not next(user for user in inventory if user["id"] == bob_id)["is_active"]


def test_certificate_filters_and_admin_password_protected_reissue(phase9):
    admin = phase9["clients"]["admin"]
    bob_id = phase9["users"]["bob"]["id"]
    assert admin.get("/api/admin/certificates?status=active").status_code == 200
    assert admin.get("/api/admin/certificates?status=unknown").status_code == 400
    endpoint = f"/api/admin/users/{bob_id}/certificates/reissue"
    assert admin.post(endpoint, json={"password": "wrong"}).status_code == 401
    response = admin.post(endpoint, json={"password": ADMIN_PASSWORD})
    assert response.status_code == 201, response.get_json()
    certs = admin.get("/api/admin/certificates?status=active").get_json()["certificates"]
    bob_certs = [cert for cert in certs if cert["user_id"] == bob_id]
    assert len(bob_certs) == 1
    assert bob_certs[0]["serial"] == response.get_json()["serial"]


def test_non_admin_cannot_use_admin_management_or_audit(phase9):
    client = phase9["clients"]["alice"]
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/activity").status_code == 403
