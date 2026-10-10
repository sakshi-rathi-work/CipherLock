# Tests file handling, access permissions, and sharing workflows.
"""Phase 7 tests: secure upload, encrypted storage, sharing and authorization.

Users are registered through the real ``/api/auth/register`` endpoint so every
account owns a genuine RSA-3072 key pair, a protected private-key envelope and a
CA-issued X.509 certificate. Nothing here touches the production database, keys or
Root CA: everything lives in pytest temporary directories.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

from app import create_app
from crypto.ca import revoke_certificate
from crypto.key_storage import unprotect_private_key
from crypto.package import TamperError, open_package, verify_package
from crypto.rsa import UnwrapError, generate_rsa_keypair, public_key_to_pem
from database.db import init_db, migrate_files_table
from models import file as file_model
from models import storage as file_storage
from models.user import get_protected_private_key

PASSWORD = "CorrectHorse9Battery"
SECRET = "phase-7-test-secret-key-32-bytes!!"
UUID_BIN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin$")
MAX_BYTES = 25 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[1]


# ----------------------------------------------------------------------------- fixtures

class Ctx:
    """Holds the isolated app and registered users for this module."""

    def __init__(self, app, base: Path):
        self.app = app
        self.base = base
        self.users: dict[str, dict] = {}
        self._n = 0

    @property
    def storage(self) -> Path:
        return Path(self.app.config["ENCRYPTED_STORAGE_DIR"])

    def new_user(self, tag: str) -> dict:
        """Register + log in a user via the real API; returns id/email/client."""
        self._n += 1
        email = f"{tag}{self._n}@example.test"
        client = self.app.test_client()
        reg = client.post("/api/auth/register",
                          json={"name": tag.title(), "email": email, "password": PASSWORD})
        assert reg.status_code == 201, reg.get_json()
        uid = reg.get_json()["user"]["id"]
        login = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
        assert login.status_code == 200
        user = {"id": uid, "email": email, "name": tag.title(), "client": client}
        self.users[tag] = user
        return user

    def sql(self, query: str, params: tuple = ()):
        con = sqlite3.connect(self.app.config["DATABASE_PATH"])
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute(query, params).fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    def file_count(self) -> int:
        return self.sql("SELECT COUNT(*) AS n FROM files")[0]["n"]

    def storage_files(self) -> set[str]:
        return {p.name for p in self.storage.iterdir()}

    def private_key(self, user_id: int):
        with self.app.app_context():
            return unprotect_private_key(
                get_protected_private_key(user_id), self.app.config["SECRET_KEY"], user_id
            )

    def activity(self, user_id: int, action: str) -> list[sqlite3.Row]:
        return self.sql(
            "SELECT * FROM activity_log WHERE user_id = ? AND action = ? ORDER BY id",
            (user_id, action),
        )


@pytest.fixture(scope="module")
def ctx(tmp_path_factory):
    base = tmp_path_factory.mktemp("phase7")
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": SECRET,
        "CIPHERLOCK_CA_PASSPHRASE": "phase-seven-ca-passphrase-32-bytes!!",
        "DATABASE_PATH": base / "phase7.db",
        "STORAGE_DIR": base / "storage",
        "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
        "CERTIFICATES_DIR": base / "certificates",
        "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": base / "certificates" / "users",
        "KEYS_DIR": base / "keys",
        "CA_KEYS_DIR": base / "keys" / "ca",
        "USER_KEYS_DIR": base / "keys" / "users",
    })
    context = Ctx(app, base)
    for tag in ("alice", "bob", "carol", "dave"):
        context.new_user(tag)
    context.sql("UPDATE users SET is_admin = 1 WHERE id = ?", (context.users["dave"]["id"],))
    return context


@pytest.fixture
def alice(ctx):
    return ctx.users["alice"]


@pytest.fixture
def bob(ctx):
    return ctx.users["bob"]


@pytest.fixture
def carol(ctx):
    return ctx.users["carol"]


def send(client, data: bytes, recipient_id, filename: str = "report.txt", **extra):
    form = {"file": (io.BytesIO(data), filename), "recipient_id": str(recipient_id), **extra}
    return client.post("/api/files/upload", data=form, content_type="multipart/form-data")


def unique(tag: str) -> bytes:
    return f"{tag}-{os.urandom(8).hex()}".encode()


@pytest.fixture
def spy_build(monkeypatch):
    """Record every call to the real Phase 6 ``build_package`` made by the route."""
    import routes.files as route_module

    calls: list[dict] = []
    real = route_module.build_package

    def wrapper(*args, **kwargs):
        package = real(*args, **kwargs)
        calls.append({"args": args, "kwargs": kwargs, "package": package})
        return package

    monkeypatch.setattr(route_module, "build_package", wrapper)
    return calls


# ------------------------------------------------------------- authentication / authorization

@pytest.mark.parametrize("method,path", [
    ("post", "/api/files/upload"),
    ("get", "/api/files/sent"),
    ("get", "/api/files/received"),
    ("get", "/api/files/stats"),
    ("get", "/api/files/1"),
])
def test_unauthenticated_requests_are_rejected(ctx, method, path):
    client = ctx.app.test_client()
    response = getattr(client, method)(path)
    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}


def test_user_sees_only_own_sent_files(ctx, alice, bob, carol):
    mine = send(alice["client"], b"alice->bob", bob["id"], "alice_own.txt").get_json()["file"]["id"]
    theirs = send(carol["client"], b"carol->bob", bob["id"], "carol_own.txt").get_json()["file"]["id"]

    alice_sent = alice["client"].get("/api/files/sent").get_json()
    ids = {f["id"] for f in alice_sent["files"]}
    assert mine in ids and theirs not in ids
    assert all(f["sender"]["id"] == alice["id"] for f in alice_sent["files"])
    assert alice_sent["total"] == len(alice_sent["files"])

    carol_sent = carol["client"].get("/api/files/sent").get_json()
    assert theirs in {f["id"] for f in carol_sent["files"]}
    assert mine not in {f["id"] for f in carol_sent["files"]}


def test_user_sees_only_files_addressed_to_them(ctx, alice, bob, carol):
    to_bob = send(alice["client"], b"for bob", bob["id"], "for_bob.txt").get_json()["file"]["id"]
    to_carol = send(alice["client"], b"for carol", carol["id"], "for_carol.txt").get_json()["file"]["id"]

    bob_inbox = bob["client"].get("/api/files/received").get_json()
    bob_ids = {f["id"] for f in bob_inbox["files"]}
    assert to_bob in bob_ids and to_carol not in bob_ids
    assert all(f["receiver"]["id"] == bob["id"] for f in bob_inbox["files"])

    carol_ids = {f["id"] for f in carol["client"].get("/api/files/received").get_json()["files"]}
    assert to_carol in carol_ids and to_bob not in carol_ids
    # The sender's own sent files never show up in their received list.
    alice_inbox = {f["id"] for f in alice["client"].get("/api/files/received").get_json()["files"]}
    assert to_bob not in alice_inbox


def test_guessing_another_users_file_id_is_indistinguishable_from_missing(ctx, alice, bob, carol):
    fid = send(alice["client"], b"private", bob["id"], "private.txt").get_json()["file"]["id"]

    assert alice["client"].get(f"/api/files/{fid}").status_code == 200  # sender
    assert bob["client"].get(f"/api/files/{fid}").status_code == 200    # recipient

    denied = carol["client"].get(f"/api/files/{fid}")
    missing = carol["client"].get("/api/files/99999999")
    huge = carol["client"].get(f"/api/files/{'9' * 30}")
    assert denied.status_code == missing.status_code == huge.status_code == 404
    assert denied.get_json() == missing.get_json() == huge.get_json() == {"error": "File not found"}
    # The denial is audited, but only against the actor.
    assert ctx.activity(carol["id"], "file_access_denied")


def test_admin_has_no_bypass_for_other_users_files(ctx, alice, bob):
    fid = send(alice["client"], b"admin must not see", bob["id"], "adm.txt").get_json()["file"]["id"]
    admin = ctx.users["dave"]
    assert admin["client"].get(f"/api/files/{fid}").status_code == 404
    assert fid not in {f["id"] for f in admin["client"].get("/api/files/sent").get_json()["files"]}
    assert fid not in {f["id"] for f in admin["client"].get("/api/files/received").get_json()["files"]}


def test_sender_identity_comes_from_the_session_not_the_client(ctx, alice, bob, carol):
    response = send(
        alice["client"], b"spoof attempt", bob["id"], "spoof.txt",
        sender_id=str(carol["id"]), user_id=str(carol["id"]), sender_email=carol["email"],
    )
    assert response.status_code == 201
    file_data = response.get_json()["file"]
    assert file_data["sender"]["id"] == alice["id"]
    row = ctx.sql("SELECT sender_id, receiver_id FROM files WHERE id = ?", (file_data["id"],))[0]
    assert (row["sender_id"], row["receiver_id"]) == (alice["id"], bob["id"])


def test_inactive_accounts_cannot_use_file_apis(ctx, bob):
    gina = ctx.new_user("gina")
    assert gina["client"].get("/api/files/sent").status_code == 200
    ctx.sql("UPDATE users SET is_active = 0 WHERE id = ?", (gina["id"],))

    for call in (
        lambda: send(gina["client"], b"x", bob["id"]),
        lambda: gina["client"].get("/api/files/sent"),
        lambda: gina["client"].get("/api/files/received"),
        lambda: gina["client"].get("/api/files/stats"),
        lambda: gina["client"].get("/api/files/1"),
    ):
        assert call().status_code == 401


def test_csrf_protection_still_applies_to_upload(ctx, alice, bob, monkeypatch):
    monkeypatch.setitem(ctx.app.config, "WTF_CSRF_ENABLED", True)
    before = ctx.file_count()
    blocked = send(alice["client"], b"no token", bob["id"], "csrf.txt")
    assert blocked.status_code == 400
    assert "csrf" in blocked.get_json()["error"].lower()
    assert ctx.file_count() == before

    token = alice["client"].get("/api/csrf-token").get_json()["csrf_token"]
    allowed = alice["client"].post(
        "/api/files/upload",
        data={"file": (io.BytesIO(b"with token"), "csrf.txt"), "recipient_id": str(bob["id"])},
        content_type="multipart/form-data",
        headers={"X-CSRFToken": token},
    )
    assert allowed.status_code == 201


# ------------------------------------------------------------------------- upload validation

def test_upload_success_contract(ctx, alice, bob):
    response = send(alice["client"], b"hello contract", bob["id"], "contract.txt")
    assert response.status_code == 201
    body = response.get_json()
    file_data = body["file"]
    assert body["duplicate"] is False
    assert file_data["original_filename"] == "contract.txt"
    assert file_data["status"] == "pending"
    assert file_data["receiver"] == {"id": bob["id"], "name": bob["name"], "email": bob["email"]}
    assert file_data["sender"]["id"] == alice["id"]
    assert file_data["size_bytes"] == len(b"hello contract")
    assert file_data["created_at"].endswith("Z")
    assert file_data["crypto"]["encryption"] == "AES-256-GCM"
    assert len(file_data["crypto"]["ciphertext_sha256"]) == 64


def test_recipient_comes_from_the_real_directory_endpoint(ctx, alice, bob):
    directory = alice["client"].get("/api/users/directory").get_json()["users"]
    target = next(u for u in directory if u["id"] == bob["id"] and u["status"] == "active")
    assert send(alice["client"], b"via directory", target["id"], "dir.txt").status_code == 201


def test_missing_file_is_rejected(ctx, alice, bob):
    before = ctx.file_count()
    response = alice["client"].post(
        "/api/files/upload", data={"recipient_id": str(bob["id"])},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "file" in response.get_json()["fields"]
    blank = alice["client"].post(
        "/api/files/upload",
        data={"file": (io.BytesIO(b"x"), ""), "recipient_id": str(bob["id"])},
        content_type="multipart/form-data",
    )
    assert blank.status_code == 400
    assert ctx.file_count() == before


def test_empty_file_is_rejected(ctx, alice, bob):
    response = send(alice["client"], b"", bob["id"], "empty.txt")
    assert response.status_code == 400
    assert "Empty" in response.get_json()["fields"]["file"]


@pytest.mark.parametrize("bad_id", ["", "abc", "-1", "1.5", "1e3", " ", "9" * 30, "0", "99999999"])
def test_invalid_or_unknown_recipient_is_rejected(ctx, alice, bad_id):
    before = ctx.file_count()
    response = send(alice["client"], b"data", bad_id)
    assert response.status_code == 400
    assert "recipient_id" in response.get_json()["fields"]
    assert ctx.file_count() == before


def test_missing_recipient_field_is_rejected(ctx, alice):
    response = alice["client"].post(
        "/api/files/upload", data={"file": (io.BytesIO(b"x"), "a.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "recipient_id" in response.get_json()["fields"]


def test_inactive_recipient_is_rejected_like_an_unknown_one(ctx, alice):
    erin = ctx.new_user("erin")
    ctx.sql("UPDATE users SET is_active = 0 WHERE id = ?", (erin["id"],))
    inactive = send(alice["client"], b"data", erin["id"])
    unknown = send(alice["client"], b"data", 98765432)
    assert inactive.status_code == unknown.status_code == 400
    assert inactive.get_json() == unknown.get_json()


def test_revoked_recipient_certificate_is_rejected(ctx, alice):
    frank = ctx.new_user("frank")
    assert send(alice["client"], b"before revoke", frank["id"], "before.txt").status_code == 201
    serial = int(ctx.sql("SELECT serial_number FROM certificates WHERE user_id = ?",
                         (frank["id"],))[0]["serial_number"])
    with ctx.app.app_context():
        assert revoke_certificate(serial)
    before = ctx.file_count()
    response = send(alice["client"], b"after revoke", frank["id"], "after.txt")
    assert response.status_code == 400
    assert "certificate" in response.get_json()["fields"]["recipient_id"]
    assert ctx.file_count() == before


def test_recipient_without_certificate_or_with_mismatched_key_is_rejected(ctx, alice):
    heidi = ctx.new_user("heidi")
    # Certificate certifies a different key than the one on the account.
    _, other_public = generate_rsa_keypair()
    ctx.sql("UPDATE users SET public_key = ? WHERE id = ?",
            (public_key_to_pem(other_public), heidi["id"]))
    assert send(alice["client"], b"x", heidi["id"]).status_code == 400

    ctx.sql("UPDATE certificates SET status = 'revoked' WHERE user_id = ?", (heidi["id"],))
    assert send(alice["client"], b"x", heidi["id"]).status_code == 400

    ivan = ctx.new_user("ivan")
    ctx.sql("DELETE FROM certificates WHERE user_id = ?", (ivan["id"],))
    assert send(alice["client"], b"x", ivan["id"]).status_code == 400


def test_oversized_upload_is_rejected_with_no_side_effects(ctx, alice, bob):
    before_rows, before_files = ctx.file_count(), ctx.storage_files()
    # Just over the application limit: handled by the route's own validation.
    over_limit = send(alice["client"], b"\0" * (MAX_BYTES + 1), bob["id"], "big.bin")
    assert over_limit.status_code == 413
    assert "25 MiB" in over_limit.get_json()["error"]
    # Far over the request cap: rejected by Flask's MAX_CONTENT_LENGTH.
    way_over = send(alice["client"], b"\0" * (MAX_BYTES + 256 * 1024), bob["id"], "huge.bin")
    assert way_over.status_code == 413
    assert way_over.get_json() == {"error": "Payload too large"}
    assert (ctx.file_count(), ctx.storage_files()) == (before_rows, before_files)


def test_file_of_exactly_the_maximum_size_is_accepted(ctx, alice, bob):
    payload = os.urandom(1024) * (MAX_BYTES // 1024)
    assert len(payload) == MAX_BYTES
    response = send(alice["client"], payload, bob["id"], "max.bin")
    assert response.status_code == 201
    assert response.get_json()["file"]["size_bytes"] == MAX_BYTES


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "etc_passwd"),
    ("..\\..\\windows\\system32\\cmd.exe", "windowssystem32cmd.exe"),
    ("my report (final).pdf", "my_report_final.pdf"),
    ("...", "file"),
    ("a" * 400 + ".txt", None),
])
def test_filenames_are_sanitized_and_never_touch_the_filesystem(ctx, alice, bob, raw, expected):
    before = ctx.storage_files()
    response = send(alice["client"], b"names", bob["id"], raw)
    assert response.status_code == 201
    stored_name = response.get_json()["file"]["original_filename"]
    if expected is not None:
        assert stored_name == expected
    else:
        assert len(stored_name) <= 255 and stored_name.endswith(".txt")
    assert "/" not in stored_name and "\\" not in stored_name and ".." not in stored_name
    new = ctx.storage_files() - before
    assert len(new) == 1 and all(UUID_BIN.match(n) for n in new)
    assert not (ctx.base / "etc").exists()


def test_malformed_requests_are_handled_safely(ctx, alice, bob):
    before = ctx.file_count()
    json_body = alice["client"].post("/api/files/upload", json={"recipient_id": bob["id"]})
    assert json_body.status_code == 400
    two_files = alice["client"].post(
        "/api/files/upload",
        data={"file": [(io.BytesIO(b"a"), "a.txt"), (io.BytesIO(b"b"), "b.txt")],
              "recipient_id": str(bob["id"])},
        content_type="multipart/form-data",
    )
    assert two_files.status_code == 400
    bad_key = send(alice["client"], b"x", bob["id"], client_request_id="bad key!")
    assert bad_key.status_code == 400
    assert alice["client"].get("/api/files/sent?limit=abc").status_code == 400
    assert alice["client"].get("/api/files/sent?limit=0").status_code == 400
    assert alice["client"].get("/api/files/sent?offset=-1").status_code == 400
    assert alice["client"].get("/api/files/upload").status_code == 405
    assert ctx.file_count() == before


def test_sending_to_yourself_is_rejected_by_policy(ctx, alice):
    before = ctx.file_count()
    response = send(alice["client"], b"note to self", alice["id"], "self.txt")
    assert response.status_code == 400
    assert "yourself" in response.get_json()["fields"]["recipient_id"]
    assert ctx.file_count() == before


def test_repeated_submission_with_same_request_id_creates_one_record(ctx, alice, bob, carol):
    key = "req-" + os.urandom(8).hex()
    first = send(alice["client"], b"once", bob["id"], "once.txt", client_request_id=key)
    second = send(alice["client"], b"once", bob["id"], "once.txt", client_request_id=key)
    assert first.status_code == 201 and second.status_code == 200
    assert second.get_json()["duplicate"] is True
    assert first.get_json()["file"]["id"] == second.get_json()["file"]["id"]
    assert len(ctx.sql("SELECT id FROM files WHERE client_request_id = ?", (key,))) == 1
    # Reusing the key for a different recipient is a conflict, not a silent resend.
    conflict = send(alice["client"], b"once", carol["id"], "once.txt", client_request_id=key)
    assert conflict.status_code == 409


def test_idempotency_survives_a_concurrent_retry_race(ctx, alice, bob, monkeypatch):
    """Simulate losing the race: the pre-check misses, the unique index catches it."""
    key = "race-" + os.urandom(8).hex()
    winner = send(alice["client"], b"winner", bob["id"], "race.txt", client_request_id=key)
    assert winner.status_code == 201
    before_files = ctx.storage_files()

    real = file_model.get_file_by_request_id
    calls = {"n": 0}

    def blind_once(sender_id, request_id):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(sender_id, request_id)

    monkeypatch.setattr(file_model, "get_file_by_request_id", blind_once)
    loser = send(alice["client"], b"winner", bob["id"], "race.txt", client_request_id=key)
    assert loser.status_code == 200 and loser.get_json()["duplicate"] is True
    assert loser.get_json()["file"]["id"] == winner.get_json()["file"]["id"]
    assert len(ctx.sql("SELECT id FROM files WHERE client_request_id = ?", (key,))) == 1
    assert ctx.storage_files() == before_files  # the loser's ciphertext was removed


def test_sender_certificate_and_key_state_is_enforced(ctx, bob):
    mallory = ctx.new_user("mallory")
    uid = mallory["id"]
    original_key = ctx.sql("SELECT encrypted_private_key AS k FROM users WHERE id = ?", (uid,))[0]["k"]
    before = ctx.file_count()
    try:
        ctx.sql("UPDATE users SET encrypted_private_key = NULL WHERE id = ?", (uid,))
        assert send(mallory["client"], b"x", bob["id"]).status_code == 422

        ctx.sql("UPDATE users SET encrypted_private_key = ? WHERE id = ?", (b"not-an-envelope" * 4, uid))
        broken = send(mallory["client"], b"x", bob["id"])
        assert broken.status_code == 500
        assert "Traceback" not in broken.get_data(as_text=True)

        # A valid envelope for a *different* key must not be accepted for signing.
        from crypto.key_storage import protect_private_key
        other_private, _ = generate_rsa_keypair()
        ctx.sql("UPDATE users SET encrypted_private_key = ? WHERE id = ?",
                (protect_private_key(other_private, SECRET, uid), uid))
        assert send(mallory["client"], b"x", bob["id"]).status_code == 422

        ctx.sql("UPDATE users SET encrypted_private_key = ? WHERE id = ?", (original_key, uid))
        assert send(mallory["client"], b"works again", bob["id"]).status_code == 201

        ctx.sql("UPDATE certificates SET status = 'revoked' WHERE user_id = ?", (uid,))
        assert send(mallory["client"], b"revoked sender", bob["id"]).status_code == 403
    finally:
        ctx.sql("UPDATE users SET encrypted_private_key = ? WHERE id = ?", (original_key, uid))
    assert ctx.file_count() == before + 1  # only the one successful send


# ------------------------------------------------------------------ cryptographic correctness

def test_upload_uses_the_existing_build_package(ctx, alice, bob, spy_build):
    plaintext = unique("spy")
    response = send(alice["client"], plaintext, bob["id"], "spy.txt")
    assert response.status_code == 201
    assert len(spy_build) == 1
    args = spy_build[0]["args"]
    assert args[0] == plaintext                # plaintext
    assert args[1] == "spy.txt"                # sanitized display name (signed in header)
    assert (args[2], args[3]) == (alice["id"], bob["id"])  # sender/receiver from trusted sources
    assert spy_build[0]["package"]["version"] == 1


def test_successful_upload_stores_a_valid_encrypted_payload(ctx, alice, bob):
    plaintext = os.urandom(5000)
    before = ctx.storage_files()
    fid = send(alice["client"], plaintext, bob["id"], "payload.bin").get_json()["file"]["id"]
    row = ctx.sql("SELECT * FROM files WHERE id = ?", (fid,))[0]
    name = row["encrypted_filename"]
    assert UUID_BIN.match(name)
    assert ctx.storage_files() - before == {name}
    stored = (ctx.storage / name).read_bytes()
    assert len(stored) == len(plaintext) + 16                     # ciphertext || 16-byte GCM tag
    assert row["status"] == "pending"
    assert len(row["encrypted_session_key"]) == 384               # RSA-3072 OAEP output
    assert len(row["nonce"]) == 12
    assert len(row["signature"]) == 384                           # RSA-3072 PSS output
    assert row["package_version"] == 1
    assert row["client_request_id"] is None
    assert x509.load_pem_x509_certificate(bytes(row["sender_certificate"])).serial_number == int(row["sender_cert_serial"])


def test_plaintext_is_never_persisted_anywhere(ctx, alice, bob):
    marker = b"TOP-SECRET-MARKER-" + os.urandom(12).hex().encode()
    plaintext = (marker + b"\n") * 20000  # > 500 KB so Werkzeug would normally spool to /tmp
    assert len(plaintext) > 500 * 1024
    response = send(alice["client"], plaintext, bob["id"], "marker.txt")
    assert response.status_code == 201
    hits = []
    for path in ctx.base.rglob("*"):
        if path.is_file() and marker in path.read_bytes():
            hits.append(path)
    assert hits == []
    assert marker not in json.dumps(response.get_json()).encode()


def test_uploads_are_buffered_in_memory_not_in_temp_files(ctx, alice, bob, monkeypatch):
    import werkzeug.formparser as formparser
    import werkzeug.wrappers.request as wrappers_request

    def forbidden(*args, **kwargs):
        raise AssertionError("uploads must not be spooled to a temporary file")

    monkeypatch.setattr(formparser, "default_stream_factory", forbidden)
    monkeypatch.setattr(wrappers_request, "default_stream_factory", forbidden, raising=False)
    response = send(alice["client"], os.urandom(2 * 1024 * 1024), bob["id"], "mem.bin")
    assert response.status_code == 201

    with ctx.app.test_request_context(
        "/x", method="POST", data={"file": (io.BytesIO(b"z" * (1024 * 1024)), "z.bin")},
        content_type="multipart/form-data",
    ) as rc:
        from flask import request
        assert isinstance(request.files["file"].stream, io.BytesIO)


def test_ciphertext_matches_recorded_sha256(ctx, alice, bob):
    fid = send(alice["client"], unique("digest") * 100, bob["id"], "digest.txt").get_json()["file"]["id"]
    row = ctx.sql("SELECT encrypted_filename, ciphertext_sha256 FROM files WHERE id = ?", (fid,))[0]
    on_disk = hashlib.sha256((ctx.storage / row["encrypted_filename"]).read_bytes()).hexdigest()
    assert on_disk == row["ciphertext_sha256"]
    detail = bob["client"].get(f"/api/files/{fid}").get_json()["file"]
    assert detail["ciphertext_sha256"] == on_disk
    assert detail["storage_status"] == "ok"


def test_every_package_field_is_persisted_and_reconstructable(ctx, alice, bob, spy_build):
    send(alice["client"], unique("fields") * 50, bob["id"], "fields.txt")
    built = spy_build[0]["package"]
    fid = ctx.sql("SELECT MAX(id) AS id FROM files")[0]["id"]
    with ctx.app.app_context():
        rebuilt = file_model.reconstruct_package(fid, bob["id"])
    assert set(rebuilt) == set(built)
    for field in built:
        assert rebuilt[field] == built[field], field
    assert rebuilt["sender_cert_serial"] == built["sender_cert_serial"]


def test_persisted_package_is_compatible_with_verify_and_open(ctx, alice, bob):
    plaintext = os.urandom(20_000)
    fid = send(alice["client"], plaintext, bob["id"], "compat.bin").get_json()["file"]["id"]
    with ctx.app.app_context():
        package = file_model.reconstruct_package(fid, bob["id"])
        report = verify_package(package, expected_sender_email=alice["email"])
        assert (report.certificate, report.signature, report.integrity, report.overall) == (
            "VALID", "VALID", "PASSED", "TRUSTED")
        assert open_package(package, ctx.private_key(bob["id"]), alice["email"]) == plaintext
        # The sender may rebuild it too (to show status), but a stranger may not.
        assert file_model.reconstruct_package(fid, alice["id"])["nonce"] == package["nonce"]
        with pytest.raises(LookupError):
            file_model.reconstruct_package(fid, ctx.users["carol"]["id"])


def test_ciphertext_cannot_be_mistaken_for_plaintext(ctx, alice, bob):
    plaintext = b"A" * 4096
    fid = send(alice["client"], plaintext, bob["id"], "aaaa.txt").get_json()["file"]["id"]
    name = ctx.sql("SELECT encrypted_filename FROM files WHERE id = ?", (fid,))[0]["encrypted_filename"]
    stored = (ctx.storage / name).read_bytes()
    assert stored != plaintext and b"A" * 16 not in stored
    assert len(set(stored)) > 200  # high-entropy, not a repeated pattern


def test_only_the_recipients_private_key_opens_the_package(ctx, alice, bob, carol):
    plaintext = unique("keys")
    fid = send(alice["client"], plaintext, bob["id"], "keys.txt").get_json()["file"]["id"]
    with ctx.app.app_context():
        package = file_model.reconstruct_package(fid, bob["id"])
        assert open_package(package, ctx.private_key(bob["id"])) == plaintext
        with pytest.raises(UnwrapError):
            open_package(package, ctx.private_key(alice["id"]))   # the sender cannot decrypt
        with pytest.raises(UnwrapError):
            open_package(package, ctx.private_key(carol["id"]))   # nor can a third party


def test_each_upload_uses_a_fresh_key_and_nonce(ctx, alice, bob, spy_build):
    send(alice["client"], b"same content", bob["id"], "same.txt")
    send(alice["client"], b"same content", bob["id"], "same.txt")
    one, two = (c["package"] for c in spy_build)
    assert one["nonce"] != two["nonce"]
    assert one["wrapped_key"] != two["wrapped_key"]
    assert one["ciphertext_with_tag"] != two["ciphertext_with_tag"]


# --------------------------------------------------------------------- storage / failures

def test_responses_never_expose_paths_keys_or_package_internals(ctx, alice, bob):
    import base64

    fid = send(alice["client"], b"leak check", bob["id"], "leak.txt").get_json()["file"]["id"]
    row = ctx.sql("SELECT * FROM files WHERE id = ?", (fid,))[0]
    secrets_in_db = [bytes(row[c]) for c in ("encrypted_session_key", "nonce", "signature", "sender_certificate")]
    needles = [row["encrypted_filename"], str(ctx.storage), str(ctx.base), "encrypted_session_key",
               "wrapped_key", "BEGIN CERTIFICATE", "PRIVATE KEY", PASSWORD,
               alice["client"].get("/api/csrf-token").get_json()["csrf_token"]]
    for blob in secrets_in_db[:3]:
        needles += [base64.b64encode(blob).decode(), blob.hex()]
    for response in (
        alice["client"].get(f"/api/files/{fid}"),
        alice["client"].get("/api/files/sent"),
        bob["client"].get("/api/files/received"),
        send(alice["client"], b"leak check 2", bob["id"], "leak2.txt"),
    ):
        text = response.get_data(as_text=True)
        for needle in needles:
            assert needle not in text, needle


@pytest.mark.parametrize("bad", [
    "../escape.bin", "/etc/passwd", "a/b.bin", "..\\x.bin", "x.bin", "", None,
    "00000000-0000-0000-0000-000000000000.bin",            # not a UUID4
    "ABCDEF12-0000-4000-8000-000000000000.bin",            # upper-case
    "00000000-0000-4000-8000-000000000000.bin/../../x",
    "00000000-0000-4000-8000-000000000000.bin\x00.txt",
])
def test_storage_paths_cannot_escape_the_storage_directory(ctx, bad):
    with ctx.app.app_context():
        with pytest.raises(file_storage.StorageError):
            file_storage.resolve_storage_path(bad)


def test_symlink_inside_storage_cannot_redirect_outside(ctx):
    outside = ctx.base / "outside.bin"
    outside.write_bytes(b"x" * 64)
    link = ctx.storage / "11111111-1111-4111-8111-111111111111.bin"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    try:
        with ctx.app.app_context():
            with pytest.raises(file_storage.StorageError):
                file_storage.resolve_storage_path(link.name)
    finally:
        link.unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_stored_ciphertext_has_restrictive_permissions(ctx, alice, bob):
    fid = send(alice["client"], b"perms", bob["id"], "perms.txt").get_json()["file"]["id"]
    name = ctx.sql("SELECT encrypted_filename FROM files WHERE id = ?", (fid,))[0]["encrypted_filename"]
    assert (ctx.storage / name).stat().st_mode & 0o777 == 0o600


def test_failed_database_insert_removes_the_new_ciphertext(ctx, alice, bob, monkeypatch):
    before_rows, before_files = ctx.file_count(), ctx.storage_files()

    def boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error (simulated)")

    monkeypatch.setattr(file_model, "create_file_record", boom)
    response = send(alice["client"], b"will fail", bob["id"], "dbfail.txt")
    assert response.status_code == 500
    text = response.get_data(as_text=True)
    assert "simulated" not in text and "Traceback" not in text and str(ctx.base) not in text
    assert (ctx.file_count(), ctx.storage_files()) == (before_rows, before_files)
    assert ctx.activity(alice["id"], "file_upload_failed")


def test_failed_filesystem_write_leaves_no_record_and_no_temp_file(ctx, alice, bob, monkeypatch):
    before_rows, before_files = ctx.file_count(), ctx.storage_files()

    def boom(*args, **kwargs):
        raise OSError(28, "No space left on device (simulated)")

    monkeypatch.setattr(file_storage.os, "replace", boom)
    response = send(alice["client"], b"will fail", bob["id"], "fsfail.txt")
    assert response.status_code == 500
    text = response.get_data(as_text=True)
    assert "simulated" not in text and str(ctx.base) not in text
    assert (ctx.file_count(), ctx.storage_files()) == (before_rows, before_files)  # no .tmp left either


def test_failure_after_commit_never_orphans_or_deletes_a_committed_payload(ctx, alice, bob, monkeypatch):
    """Row, audit entry and ciphertext are committed together; a later error must not split them."""
    import routes.files as route_module

    before_rows, before_files = ctx.file_count(), ctx.storage_files()
    uploads_logged = len(ctx.activity(alice["id"], "file_upload"))

    def late_failure(*args, **kwargs):
        raise RuntimeError("failure after commit (simulated)")

    monkeypatch.setattr(route_module.file_model, "get_file_for_sender", late_failure)
    response = send(alice["client"], b"late", bob["id"], "late.txt")
    assert response.status_code == 500

    assert ctx.file_count() == before_rows + 1
    new_files = ctx.storage_files() - before_files
    assert len(new_files) == 1
    row = ctx.sql("SELECT encrypted_filename FROM files ORDER BY id DESC LIMIT 1")[0]
    assert {row["encrypted_filename"]} == new_files           # record still points at its payload
    assert len(ctx.activity(alice["id"], "file_upload")) == uploads_logged + 1


def test_missing_ciphertext_is_reported_safely(ctx, alice, bob):
    fid = send(alice["client"], b"vanishing", bob["id"], "gone.txt").get_json()["file"]["id"]
    name = ctx.sql("SELECT encrypted_filename FROM files WHERE id = ?", (fid,))[0]["encrypted_filename"]
    (ctx.storage / name).unlink()

    detail = bob["client"].get(f"/api/files/{fid}")
    assert detail.status_code == 200
    data = detail.get_json()["file"]
    assert data["storage_status"] == "missing" and data["size_bytes"] is None
    assert name not in detail.get_data(as_text=True) and str(ctx.base) not in detail.get_data(as_text=True)
    listing = bob["client"].get("/api/files/received")
    assert listing.status_code == 200
    with ctx.app.app_context():
        with pytest.raises(file_storage.StoredFileMissingError) as raised:
            file_model.reconstruct_package(fid, bob["id"])
        assert str(ctx.base) not in str(raised.value)


def test_corrupted_ciphertext_is_detected(ctx, alice, bob):
    fid = send(alice["client"], unique("corrupt") * 40, bob["id"], "corrupt.txt").get_json()["file"]["id"]
    name = ctx.sql("SELECT encrypted_filename FROM files WHERE id = ?", (fid,))[0]["encrypted_filename"]
    path = ctx.storage / name
    original = path.read_bytes()

    flipped = bytearray(original)
    flipped[3] ^= 0x01
    path.write_bytes(bytes(flipped))
    assert bob["client"].get(f"/api/files/{fid}").get_json()["file"]["storage_status"] == "corrupted"
    with ctx.app.app_context():
        package = file_model.reconstruct_package(fid, bob["id"])
        assert verify_package(package).overall == "POSSIBLE TAMPERING"
        with pytest.raises(TamperError):
            open_package(package, ctx.private_key(bob["id"]))

    path.write_bytes(original[:5])  # truncated below the GCM tag size
    assert bob["client"].get(f"/api/files/{fid}").get_json()["file"]["storage_status"] == "corrupted"
    with ctx.app.app_context():
        with pytest.raises(file_storage.StoredFileCorruptError):
            file_model.reconstruct_package(fid, bob["id"])

    path.write_bytes(original)
    assert bob["client"].get(f"/api/files/{fid}").get_json()["file"]["storage_status"] == "ok"


# ------------------------------------------------------------- listing behaviour, audit log

def test_listings_are_newest_first_and_paginate_stably(ctx, alice):
    sender = ctx.new_user("lister")
    ids = [send(sender["client"], f"n{i}".encode(), alice["id"], f"order_{i}.txt").get_json()["file"]["id"]
           for i in range(5)]
    page1 = sender["client"].get("/api/files/sent?limit=2&offset=0").get_json()
    page2 = sender["client"].get("/api/files/sent?limit=2&offset=2").get_json()
    page3 = sender["client"].get("/api/files/sent?limit=2&offset=4").get_json()
    seen = [f["id"] for page in (page1, page2, page3) for f in page["files"]]
    assert seen == sorted(ids, reverse=True)
    assert page1["total"] == 5 and page1["limit"] == 2
    assert sender["client"].get("/api/files/sent?limit=1000").get_json()["limit"] == 100


def test_search_filters_by_filename_and_counterpart_and_is_injection_safe(ctx, alice):
    sender = ctx.new_user("searcher")
    send(sender["client"], b"1", alice["id"], "quarterly_budget.xlsx")
    send(sender["client"], b"2", alice["id"], "holiday_photo.png")
    names = lambda q: [f["original_filename"] for f in sender["client"].get(
        "/api/files/sent", query_string={"q": q}).get_json()["files"]]
    assert names("budget") == ["quarterly_budget.xlsx"]
    assert names("ALICE") == ["holiday_photo.png", "quarterly_budget.xlsx"]
    assert names("%") == [] and names("_") == names("_")           # wildcards are escaped
    assert names("' OR 1=1 --") == []
    assert ctx.sql("SELECT COUNT(*) AS n FROM files")[0]["n"] > 0   # table intact


def test_stats_endpoint_counts_for_the_current_user_only(ctx, bob):
    user = ctx.new_user("counter")
    assert user["client"].get("/api/files/stats").get_json() == {"sent_count": 0, "received_count": 0}
    send(user["client"], b"1", bob["id"], "c1.txt")
    send(bob["client"], b"2", user["id"], "c2.txt")
    send(bob["client"], b"3", user["id"], "c3.txt")
    assert user["client"].get("/api/files/stats").get_json() == {"sent_count": 1, "received_count": 2}


def test_activity_logging_is_meaningful_throttled_and_secret_free(ctx, alice, bob):
    quiet = ctx.new_user("auditor")
    send(quiet["client"], b"audit me", bob["id"], "audit_secret_name.txt")
    send(quiet["client"], b"x", quiet["id"])             # rejected (self-send)
    for _ in range(3):                                   # throttled: one entry for repeated refreshes
        quiet["client"].get("/api/files/sent")
        bob["client"].get("/api/files/received")
    quiet["client"].get("/api/files/424242")

    rows = ctx.sql("SELECT action, detail FROM activity_log WHERE user_id = ?", (quiet["id"],))
    actions = [r["action"] for r in rows]
    assert actions.count("file_upload") == 1
    assert actions.count("file_upload_failed") == 1
    assert actions.count("file_list_sent") == 1
    assert actions.count("file_access_denied") == 1
    assert len(ctx.activity(bob["id"], "file_list_received")) == 1
    joined = " ".join(f"{r['action']} {r['detail']}" for r in rows)
    for secret in ("audit_secret_name", "audit me", PASSWORD, "PRIVATE KEY"):
        assert secret not in joined
    api_activity = quiet["client"].get("/api/auth/activity").get_json()["activity"]
    assert any(item["action"] == "file_upload" for item in api_activity)


# ------------------------------------------------------------------------------ migration

OLD_SCHEMA_FILES = """
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE, password_hash TEXT, public_key BLOB, encrypted_private_key BLOB,
    certificate BLOB, is_admin INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id), receiver_id INTEGER NOT NULL REFERENCES users(id),
    original_filename TEXT NOT NULL, encrypted_filename TEXT NOT NULL UNIQUE,
    encrypted_session_key BLOB, nonce BLOB, signature BLOB, sender_certificate BLOB,
    ciphertext_sha256 TEXT, status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    certificate BLOB NOT NULL, serial_number TEXT NOT NULL UNIQUE, issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE activity_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
    detail TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
"""


def _columns(path, table="files"):
    con = sqlite3.connect(path)
    try:
        return {row[1]: row for row in con.execute(f"PRAGMA table_info({table})")}
    finally:
        con.close()


def test_migration_upgrades_a_phase6_database_without_losing_data(ctx, tmp_path):
    path = tmp_path / "old.db"
    legacy_cert = ctx.sql("SELECT certificate, serial_number FROM certificates LIMIT 1")[0]
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA_FILES)
    con.execute("INSERT INTO users (name, email) VALUES ('A','a@x.test'), ('B','b@x.test')")
    con.execute("INSERT INTO activity_log (user_id, action, detail) VALUES (1, 'login', 'ip=1')")
    con.execute(
        "INSERT INTO files (sender_id, receiver_id, original_filename, encrypted_filename, sender_certificate)"
        " VALUES (1, 2, 'legacy.txt', 'legacy.bin', ?)", (legacy_cert["certificate"],))
    con.commit(); con.close()

    assert "package_version" not in _columns(path)
    init_db(path)
    init_db(path)  # idempotent

    cols = _columns(path)
    assert {"package_version", "sender_cert_serial", "client_request_id"} <= set(cols)
    con = sqlite3.connect(path); con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM files").fetchone()
    assert (row["original_filename"], row["package_version"]) == ("legacy.txt", 1)
    assert row["sender_cert_serial"] == legacy_cert["serial_number"]       # back-filled from the PEM
    assert con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    assert con.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0] == 1
    indexes = {r[1] for r in con.execute("PRAGMA index_list(files)")}
    assert {"idx_files_sender_request", "idx_files_sender_created", "idx_files_receiver_created"} <= indexes
    con.close()


def test_migration_on_a_current_database_is_a_no_op(ctx):
    con = sqlite3.connect(ctx.app.config["DATABASE_PATH"])
    try:
        assert migrate_files_table(con) == []
    finally:
        con.close()


def test_unique_index_blocks_duplicate_request_ids_per_sender_only(ctx, alice, bob):
    key = "uniq-" + os.urandom(6).hex()
    con = sqlite3.connect(ctx.app.config["DATABASE_PATH"])
    insert = ("INSERT INTO files (sender_id, receiver_id, original_filename, encrypted_filename, client_request_id)"
              " VALUES (?, ?, 'f', ?, ?)")
    try:
        con.execute(insert, (alice["id"], bob["id"], "u1.bin", key))
        con.execute(insert, (bob["id"], alice["id"], "u2.bin", key))        # other sender: allowed
        con.execute(insert, (alice["id"], bob["id"], "u3.bin", None))        # NULL keys: unconstrained
        con.execute(insert, (alice["id"], bob["id"], "u4.bin", None))
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(insert, (alice["id"], bob["id"], "u5.bin", key))
        con.rollback()
    finally:
        con.close()


# ------------------------------------------------------------------------------ regression

def test_phase6_cli_end_to_end_still_passes():
    result = subprocess.run(
        [os.sys.executable, "scripts/e2e_cli.py"], cwd=REPO_ROOT,
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "9/9 attack cases matched" in result.stdout
