"""Phase 8 End-to-End Verification Pipeline & Decryption Tests.

Requirements tested:
1. Happy path: User A (Alice) sends a file to User B (Vidhi/Bob) -> B verifies (status TRUSTED,
   panels VALID, integrity PASSED, files.status set to 'verified') -> B enters password and
   downloads -> decrypted plaintext matches original bytes byte-for-byte.
2. Authorization: User C (Carol) attempts verify and download on A->B file -> 404 Not Found.
3. Password authentication: B with a wrong password cannot download -> 401 error, no file.
4. Tamper detection (Fail-Closed): Flipping 1 byte in the stored .bin causes verify to show
   Signature INVALID / Integrity FAILED, and download is refused with the exact required failure
   message: "Signature verification failed. File may have been modified or sender authenticity could not be established."
5. Sender cannot download their own file -> 404 Not Found.
6. Cache-Control: no-store asserted on download response.
"""
from __future__ import annotations

import io
import os
import sqlite3
from pathlib import Path

import pytest

from app import create_app
from crypto.ca import revoke_certificate
from crypto.package import SIGNATURE_FAILURE_MESSAGE
from models import file as file_model

PASSWORD = "CorrectHorse9Battery"
SECRET = "phase-8-flow-test-secret-key-32b!!"


class FlowCtx:
    """Isolated test environment for Phase 8 flow verification."""

    def __init__(self, app, base: Path):
        self.app = app
        self.base = base
        self.users: dict[str, dict] = {}
        self._counter = 0

    @property
    def storage_dir(self) -> Path:
        return Path(self.app.config["ENCRYPTED_STORAGE_DIR"])

    def new_user(self, name: str) -> dict:
        self._counter += 1
        email = f"{name.lower()}{self._counter}@cipherlock.test"
        client = self.app.test_client()

        # Register user with genuine RSA-3072 key pair & certificate
        res = client.post(
            "/api/auth/register",
            json={"name": name, "email": email, "password": PASSWORD},
        )
        assert res.status_code == 201, res.get_json()
        uid = res.get_json()["user"]["id"]

        # Authenticate session
        login_res = client.post(
            "/api/auth/login",
            json={"email": email, "password": PASSWORD},
        )
        assert login_res.status_code == 200

        user = {"id": uid, "name": name, "email": email, "client": client}
        self.users[name.lower()] = user
        return user

    def sql(self, query: str, params: tuple = ()):
        con = sqlite3.connect(self.app.config["DATABASE_PATH"])
        con.row_factory = sqlite3.Row
        try:
            cur = con.execute(query, params)
            rows = cur.fetchall()
            con.commit()
            return rows
        finally:
            con.close()


@pytest.fixture(scope="module")
def flow_ctx(tmp_path_factory):
    base = tmp_path_factory.mktemp("phase8_flow")
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": SECRET,
        "CIPHERLOCK_CA_PASSPHRASE": "phase-eight-ca-passphrase-32-bytes!!",
        "DATABASE_PATH": base / "phase8.db",
        "STORAGE_DIR": base / "storage",
        "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
        "CERTIFICATES_DIR": base / "certificates",
        "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": base / "certificates" / "users",
        "KEYS_DIR": base / "keys",
        "CA_KEYS_DIR": base / "keys" / "ca",
        "USER_KEYS_DIR": base / "keys" / "users",
    })
    ctx = FlowCtx(app, base)
    ctx.new_user("Alice")
    ctx.new_user("Bob")
    ctx.new_user("Carol")
    return ctx


def _send_file(sender_client, recipient_id: int, content: bytes, filename: str) -> dict:
    """Helper to upload and encrypt a file for a recipient."""
    data = {
        "file": (io.BytesIO(content), filename),
        "recipient_id": str(recipient_id),
    }
    res = sender_client.post(
        "/api/files/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert res.status_code == 201, res.get_json()
    return res.get_json()["file"]


def test_happy_path_verify_and_download(flow_ctx):
    """Happy path: Alice sends to Bob -> Bob verifies -> Bob enters password -> downloads identical plaintext."""
    alice = flow_ctx.users["alice"]
    bob = flow_ctx.users["bob"]

    original_content = b"Top secret college research document contents \x00\xff\x42."
    original_filename = "crypto_project_report.pdf"

    # Step 1: Alice uploads encrypted file for Bob
    file_info = _send_file(alice["client"], bob["id"], original_content, original_filename)
    file_id = file_info["id"]

    # Step 2: Bob lists received files
    list_res = bob["client"].get("/received")
    assert list_res.status_code == 200
    assert original_filename in list_res.get_data(as_text=True)

    # Step 3: Bob verifies the file (HTML view)
    verify_html_res = bob["client"].get(f"/files/{file_id}/verify")
    assert verify_html_res.status_code == 200
    html_text = verify_html_res.get_data(as_text=True)
    assert "STATUS: TRUSTED" in html_text
    assert "CIPHERLOCK SECURITY CHECK" in html_text
    assert "Certificate: VALID" in html_text
    assert "Signature: VALID" in html_text
    assert "Integrity: PASSED" in html_text

    # Step 4: Bob verifies the file via JSON API
    verify_api_res = bob["client"].get(f"/api/files/{file_id}/verify")
    assert verify_api_res.status_code == 200
    data = verify_api_res.get_json()
    assert data["report"]["overall"] == "TRUSTED"
    assert data["report"]["certificate"] == "VALID"
    assert data["report"]["signature"] == "VALID"
    assert data["report"]["integrity"] == "PASSED"
    assert data["can_decrypt"] is True

    # Database files.status should now be 'verified'
    row = flow_ctx.sql("SELECT status FROM files WHERE id = ?", (file_id,))[0]
    assert row["status"] == "verified"

    # Step 5: Bob downloads the file with password
    download_res = bob["client"].post(
        f"/files/{file_id}/download",
        data={"password": PASSWORD},
    )
    assert download_res.status_code == 200
    assert download_res.data == original_content
    assert download_res.headers.get("Cache-Control") == "no-store"
    assert "attachment" in download_res.headers.get("Content-Disposition", "")
    assert original_filename in download_res.headers.get("Content-Disposition", "")

    # Step 6: Bob downloads via API endpoint with JSON body
    api_download_res = bob["client"].post(
        f"/api/files/{file_id}/download",
        json={"password": PASSWORD},
    )
    assert api_download_res.status_code == 200
    assert api_download_res.data == original_content
    assert api_download_res.headers.get("Cache-Control") == "no-store"


def test_unauthorized_user_cannot_verify_or_download(flow_ctx):
    """User C (Carol) cannot verify or download Alice's file to Bob -> 404."""
    alice = flow_ctx.users["alice"]
    bob = flow_ctx.users["bob"]
    carol = flow_ctx.users["carol"]

    file_info = _send_file(alice["client"], bob["id"], b"Private between A and B", "secret_ab.txt")
    file_id = file_info["id"]

    # Carol attempts verify -> 404
    res_verify_web = carol["client"].get(f"/files/{file_id}/verify")
    assert res_verify_web.status_code == 404

    res_verify_api = carol["client"].get(f"/api/files/{file_id}/verify")
    assert res_verify_api.status_code == 404

    # Carol attempts download -> 404
    res_down_web = carol["client"].post(
        f"/files/{file_id}/download",
        data={"password": PASSWORD},
    )
    assert res_down_web.status_code == 404

    res_down_api = carol["client"].post(
        f"/api/files/{file_id}/download",
        json={"password": PASSWORD},
    )
    assert res_down_api.status_code == 404


def test_sender_cannot_download_their_own_file(flow_ctx):
    """Alice (the sender) cannot download or verify the file intended for Bob -> 404."""
    alice = flow_ctx.users["alice"]
    bob = flow_ctx.users["bob"]

    file_info = _send_file(alice["client"], bob["id"], b"Sender cannot download", "sender_test.txt")
    file_id = file_info["id"]

    # Alice attempts verify -> 404 (receiver only)
    res_verify = alice["client"].get(f"/files/{file_id}/verify")
    assert res_verify.status_code == 404

    # Alice attempts download -> 404
    res_down = alice["client"].post(
        f"/files/{file_id}/download",
        data={"password": PASSWORD},
    )
    assert res_down.status_code == 404


def test_wrong_password_blocks_download(flow_ctx):
    """Bob providing an incorrect password is refused download -> 401 error, no file."""
    alice = flow_ctx.users["alice"]
    bob = flow_ctx.users["bob"]

    original = b"Protected data for password check."
    file_info = _send_file(alice["client"], bob["id"], original, "password_check.bin")
    file_id = file_info["id"]

    # Download with wrong password via API
    res = bob["client"].post(
        f"/api/files/{file_id}/download",
        json={"password": "TotallyWrongPassword999!"},
    )
    assert res.status_code == 401
    assert "Incorrect password" in res.get_json()["error"]
    assert res.data != original


def test_tampered_stored_file_fails_verification_and_blocks_download(flow_ctx):
    """Flipping a byte in the stored .bin makes verify show Signature INVALID / Integrity FAILED
    and download is refused with the exact failure message."""
    alice = flow_ctx.users["alice"]
    bob = flow_ctx.users["bob"]

    file_info = _send_file(alice["client"], bob["id"], b"Untampered plaintext", "tamper_victim.txt")
    file_id = file_info["id"]

    # Locate the encrypted file on disk
    row = flow_ctx.sql("SELECT encrypted_filename FROM files WHERE id = ?", (file_id,))[0]
    bin_path = flow_ctx.storage_dir / row["encrypted_filename"]
    assert bin_path.exists()

    # Tamper with the ciphertext by flipping the first byte
    ciphertext_bytes = bytearray(bin_path.read_bytes())
    ciphertext_bytes[0] ^= 0x01
    bin_path.write_bytes(bytes(ciphertext_bytes))

    # Verification must detect the tampering
    verify_res = bob["client"].get(f"/api/files/{file_id}/verify")
    assert verify_res.status_code == 200
    report = verify_res.get_json()["report"]

    assert report["signature"] == "INVALID"
    assert report["integrity"] == "FAILED"
    assert report["overall"] == "POSSIBLE TAMPERING"
    assert verify_res.get_json()["can_decrypt"] is False

    # Status in database should be 'failed'
    db_status = flow_ctx.sql("SELECT status FROM files WHERE id = ?", (file_id,))[0]["status"]
    assert db_status == "failed"

    # Attempting to download the tampered file must fail and return the EXACT required message
    download_res = bob["client"].post(
        f"/api/files/{file_id}/download",
        json={"password": PASSWORD},
    )
    assert download_res.status_code == 400
    err_body = download_res.get_json()
    assert err_body["error"] == SIGNATURE_FAILURE_MESSAGE
    assert err_body["error"] == (
        "Signature verification failed. File may have been modified or sender authenticity could not be established."
    )


def test_revoked_sender_certificate_blocks_download(flow_ctx):
    """Revoking the sender's certificate results in UNTRUSTED SENDER and download refusal."""
    revoked_sender = flow_ctx.new_user("Mallory")
    bob = flow_ctx.users["bob"]

    file_info = _send_file(revoked_sender["client"], bob["id"], b"Mallory payload", "mallory.txt")
    file_id = file_info["id"]

    # Revoke Mallory's certificate in the DB
    cert_row = flow_ctx.sql(
        "SELECT serial_number FROM certificates WHERE user_id = ? AND status = 'active'",
        (revoked_sender["id"],),
    )[0]
    with flow_ctx.app.app_context():
        revoke_certificate(int(cert_row["serial_number"]))

    # Verification must flag the certificate as INVALID
    verify_res = bob["client"].get(f"/api/files/{file_id}/verify")
    assert verify_res.status_code == 200
    report = verify_res.get_json()["report"]
    assert report["certificate"] == "INVALID"
    assert report["overall"] == "UNTRUSTED SENDER"

    # Download must be refused
    down_res = bob["client"].post(
        f"/api/files/{file_id}/download",
        json={"password": PASSWORD},
    )
    assert down_res.status_code == 400
    assert down_res.get_json()["error"] == SIGNATURE_FAILURE_MESSAGE
