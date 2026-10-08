"""Focused tests for Phase 3 AES, RSA, key protection, and registration."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from app import create_app
from crypto.aes import DecryptionError, decrypt_bytes, encrypt_bytes, generate_session_key
from crypto.key_storage import (
    PrivateKeyProtectionError,
    protect_private_key,
    unprotect_private_key,
)
from crypto.rsa import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
)

_APP_SECRET = "phase-three-test-secret-with-at-least-32-bytes"


@pytest.fixture
def auth_client(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": _APP_SECRET,
        "DATABASE_PATH": tmp_path / "phase3.db",
        "STORAGE_DIR": tmp_path / "storage",
        "ENCRYPTED_STORAGE_DIR": tmp_path / "storage" / "encrypted",
        "CERTIFICATES_DIR": tmp_path / "certificates",
        "CA_CERTIFICATES_DIR": tmp_path / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": tmp_path / "certificates" / "users",
        "KEYS_DIR": tmp_path / "keys",
        "CA_KEYS_DIR": tmp_path / "keys" / "ca",
        "USER_KEYS_DIR": tmp_path / "keys" / "users",
    })
    return app.test_client(), app.config["DATABASE_PATH"]


def _register(client, email="crypto-user@example.com"):
    return _post_json(
        client,
        "/api/auth/register",
        {
            "name": "Crypto User",
            "email": email,
            "password": "ValidPassword123!",
        },
    )


def _post_json(client: Any, path: str, payload: dict[str, str]):
    token_response = client.get("/api/csrf-token")
    token = token_response.get_json()["csrf_token"]
    return client.post(
        path,
        json=payload,
        headers={"X-CSRFToken": token},
    )


def test_aes_gcm_round_trip_and_fresh_nonce():
    key = generate_session_key()
    plaintext = b"CipherLock AES-GCM test payload\x00"
    aad = b"metadata authenticated but not encrypted"

    nonce_1, ciphertext_1 = encrypt_bytes(key, plaintext, aad)
    nonce_2, ciphertext_2 = encrypt_bytes(key, plaintext, aad)

    assert len(key) == 32
    assert len(nonce_1) == 12
    assert len(ciphertext_1) >= len(plaintext) + 16
    assert nonce_1 != nonce_2
    assert (nonce_1, ciphertext_1) != (nonce_2, ciphertext_2)
    assert decrypt_bytes(key, nonce_1, ciphertext_1, aad) == plaintext
    assert decrypt_bytes(key, nonce_2, ciphertext_2, aad) == plaintext


@pytest.mark.parametrize("tamper", ["wrong_key", "ciphertext", "nonce", "tag"])
def test_aes_gcm_rejects_invalid_authentication(tamper):
    key = generate_session_key()
    nonce, encrypted = encrypt_bytes(key, b"authenticated data", b"context")

    if tamper == "wrong_key":
        key = generate_session_key()
    elif tamper == "ciphertext":
        encrypted = bytes((encrypted[0] ^ 1,)) + encrypted[1:]
    elif tamper == "nonce":
        nonce = bytes((nonce[0] ^ 1,)) + nonce[1:]
    else:
        encrypted = encrypted[:-1] + bytes((encrypted[-1] ^ 1,))

    with pytest.raises(DecryptionError):
        decrypt_bytes(key, nonce, encrypted, b"context")


def test_rsa_key_generation_and_pem_serialization():
    private_key, public_key = generate_rsa_keypair()
    private_pem = private_key_to_pem(private_key)
    public_pem = public_key_to_pem(public_key)
    loaded_private = load_private_key(private_pem)
    loaded_public = load_public_key(public_pem)

    assert isinstance(private_key, RSAPrivateKey)
    assert isinstance(public_key, RSAPublicKey)
    assert private_key.key_size == public_key.key_size == 3072
    assert loaded_private.private_numbers() == private_key.private_numbers()
    assert loaded_public.public_numbers() == public_key.public_numbers()
    assert b"PRIVATE KEY" not in public_pem

    session_key = generate_session_key()
    wrapped = loaded_public.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    assert loaded_private.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ) == session_key


def test_private_key_protection_authenticates_secret_and_user():
    private_key, _ = generate_rsa_keypair()
    pem = private_key_to_pem(private_key)
    protected = protect_private_key(private_key, _APP_SECRET, 42)

    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pem not in protected
    assert b"PRIVATE KEY" not in protected
    recovered = unprotect_private_key(protected, _APP_SECRET, 42)
    assert recovered.private_numbers() == private_key.private_numbers()

    with pytest.raises(PrivateKeyProtectionError):
        unprotect_private_key(protected, "a-different-protection-secret-of-32-bytes", 42)
    with pytest.raises(PrivateKeyProtectionError):
        unprotect_private_key(protected, _APP_SECRET, 43)

    changed = protected[:-1] + bytes((protected[-1] ^ 1,))
    with pytest.raises(PrivateKeyProtectionError):
        unprotect_private_key(changed, _APP_SECRET, 42)


def test_registration_persists_protected_rsa_key_not_in_response(auth_client):
    client, database_path = auth_client
    response = _register(client)

    assert response.status_code == 201
    user_id = response.get_json()["user"]["id"]
    response_text = response.get_data(as_text=True)
    assert "public_key" not in response_text
    assert "encrypted_private_key" not in response_text
    assert "PRIVATE KEY" not in response_text

    login_response = _post_json(
        client,
        "/api/auth/login",
        {"email": "crypto-user@example.com", "password": "ValidPassword123!"},
    )
    assert login_response.status_code == 200
    profile_response = client.get("/api/auth/me")
    assert profile_response.status_code == 200
    assert "PRIVATE KEY" not in profile_response.get_data(as_text=True)
    assert "encrypted_private_key" not in profile_response.get_data(as_text=True)

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            "SELECT public_key, encrypted_private_key FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    public_pem, protected_private_key = row
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert b"PRIVATE KEY" not in protected_private_key
    public_key = load_public_key(public_pem)
    private_key = unprotect_private_key(protected_private_key, _APP_SECRET, user_id)
    assert public_key.public_numbers() == private_key.public_key().public_numbers()


def test_registration_rolls_back_if_crypto_provisioning_fails(auth_client, monkeypatch):
    import routes.auth as auth_routes

    client, database_path = auth_client

    def fail_provisioning(*_args, **_kwargs):
        del _args, _kwargs
        raise RuntimeError("provisioning failed")

    monkeypatch.setattr(auth_routes, "provision_user_crypto", fail_provisioning)
    response = _register(client, "rollback-crypto@example.com")
    assert response.status_code == 500
    assert response.get_json() == {"error": "An unexpected error occurred."}

    connection = sqlite3.connect(database_path)
    try:
        users = connection.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            ("rollback-crypto@example.com",),
        ).fetchone()[0]
        activities = connection.execute(
            "SELECT COUNT(*) FROM activity_log WHERE detail LIKE ?",
            ("%rollback-crypto%",),
        ).fetchone()[0]
    finally:
        connection.close()
    assert users == 0
    assert activities == 0
