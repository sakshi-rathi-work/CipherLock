"""Phase 10 – Key Management System (KMS) test suite.

Comprehensive tests covering:
- Section 1: Cryptographic primitives (Master key derivation, KEK protection, DEK wrapping, envelope encryption)
- Section 2: KMS service layer (KEK lifecycle, rotation policies, DEK registry, compromise/recovery, audit logs)
- Section 3: KMS admin API routes (Authentication, authorization, key management, rewrapping, policy, audit)
"""
from __future__ import annotations

import os
import sqlite3
from typing import Any

import pytest

from app import create_app
from crypto.kms import (
    DEKWrapError,
    KEKProtectionError,
    MasterKeyError,
    ProtectedKEK,
    WrappedDEK,
    derive_master_key,
    envelope_decrypt,
    envelope_encrypt,
    generate_dek,
    generate_kek,
    protect_kek,
    rewrap_dek,
    unprotect_kek,
    unwrap_dek,
    wrap_dek,
)
from database.db import get_db
from models.kms import (
    KEKNotFoundError,
    KMSError,
    NoActiveKEKError,
    PolicyViolationError,
    check_rotation_needed,
    compromise_kek,
    create_kek,
    destroy_kek,
    ensure_kms_initialized,
    get_active_kek,
    get_active_kek_row,
    get_dek_for_file,
    get_dek_info,
    get_kek_by_version,
    get_kms_status,
    get_master_key,
    get_rotation_policy,
    list_kek_versions,
    list_kms_audit,
    log_kms_event,
    perform_auto_rotation,
    recover_from_compromise,
    register_dek,
    rewrap_all_deks,
    rotate_kek,
    update_rotation_policy,
)

_APP_SECRET = "phase-ten-test-secret-with-at-least-32-bytes"


# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def app(tmp_path):
    """Provide an isolated test application with temporary storage and database."""
    test_app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": _APP_SECRET,
        "CIPHERLOCK_CA_PASSPHRASE": "phase-ten-test-ca-passphrase-32b!!",
        "DATABASE_PATH": tmp_path / "kms_test.db",
        "STORAGE_DIR": tmp_path / "storage",
        "ENCRYPTED_STORAGE_DIR": tmp_path / "storage" / "encrypted",
        "CERTIFICATES_DIR": tmp_path / "certificates",
        "CA_CERTIFICATES_DIR": tmp_path / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": tmp_path / "certificates" / "users",
        "KEYS_DIR": tmp_path / "keys",
        "CA_KEYS_DIR": tmp_path / "keys" / "ca",
        "USER_KEYS_DIR": tmp_path / "keys" / "users",
    })
    return test_app


@pytest.fixture
def client(app):
    """Provide a test client for the test application."""
    return app.test_client()


def _create_admin_session(app, client, email="admin@test.com", password="TestPassword123!") -> int:
    """Register a user, promote to admin, login, and return user_id."""
    resp = client.post("/api/auth/register", json={
        "name": "Admin User",
        "email": email,
        "password": password,
    })
    assert resp.status_code == 201, resp.get_json()
    user_id = resp.get_json()["user"]["id"]

    conn = sqlite3.connect(app.config["DATABASE_PATH"])
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
    })
    assert resp.status_code == 200, resp.get_json()
    return user_id


def _create_user_session(app, client, email="user@test.com", password="TestPassword123!") -> int:
    """Register a regular user (is_admin=0), login, and return user_id."""
    resp = client.post("/api/auth/register", json={
        "name": "Regular User",
        "email": email,
        "password": password,
    })
    assert resp.status_code == 201, resp.get_json()
    user_id = resp.get_json()["user"]["id"]

    resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
    })
    assert resp.status_code == 200, resp.get_json()
    return user_id


def _create_dummy_file(app, user_id: int | None = None, filename: str = "test.txt") -> int:
    """Insert a dummy user and files table row, returning the new file_id."""
    with app.app_context():
        db = get_db()
        if user_id is None:
            row = db.execute("SELECT id FROM users LIMIT 1").fetchone()
            if row:
                user_id = row[0]
            else:
                cursor = db.execute(
                    "INSERT INTO users (name, email) VALUES (?, ?)",
                    ("Dummy File Owner", f"dummy_{os.urandom(6).hex()}@test.com"),
                )
                db.commit()
                user_id = cursor.lastrowid

        enc_filename = f"enc_{os.urandom(8).hex()}.dat"
        cursor = db.execute(
            "INSERT INTO files (original_filename, encrypted_filename, sender_id, receiver_id, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (filename, enc_filename, user_id, user_id, "pending"),
        )
        db.commit()
        return cursor.lastrowid


# ---------------------------------------------------------------------------
# Section 1: Crypto Layer Tests (no Flask context needed)
# ---------------------------------------------------------------------------

def test_master_key_derivation_deterministic():
    """1. Derive master key deterministically with same secret+salt; different salt gives different key."""
    secret = "phase-ten-test-secret-with-at-least-32-bytes"
    salt1 = os.urandom(32)
    key1, returned_salt1 = derive_master_key(secret, salt1)
    key2, returned_salt2 = derive_master_key(secret, salt1)

    assert key1 == key2
    assert returned_salt1 == salt1
    assert returned_salt2 == salt1
    assert len(key1) == 32

    # Different salt produces a different master key
    salt2 = os.urandom(32)
    key3, _ = derive_master_key(secret, salt2)
    assert key1 != key3

    # Different secret produces a different master key
    key4, _ = derive_master_key("another-secret-value-of-sufficient-length", salt1)
    assert key1 != key4

    # Derivation works identically with bytes secret input
    key5, _ = derive_master_key(secret.encode("utf-8"), salt1)
    assert key5 == key1

    # Default salt generation when salt is None
    key_fresh, salt_fresh = derive_master_key(secret)
    assert len(key_fresh) == 32
    assert len(salt_fresh) == 32


def test_master_key_rejects_empty_secret():
    """2. Derive master key raises MasterKeyError on empty or invalid secret."""
    with pytest.raises(MasterKeyError, match="must not be empty"):
        derive_master_key("")
    with pytest.raises(MasterKeyError, match="must not be empty"):
        derive_master_key(b"")
    with pytest.raises(MasterKeyError, match="must be str or bytes"):
        derive_master_key(12345)  # type: ignore[arg-type]


def test_master_key_rejects_short_salt():
    """3. Derive master key raises MasterKeyError if salt is shorter than 16 bytes."""
    with pytest.raises(MasterKeyError, match="at least 16 bytes"):
        derive_master_key("valid-secret", salt=b"too_short")
    with pytest.raises(MasterKeyError, match="at least 16 bytes"):
        derive_master_key("valid-secret", salt=b"123456789012345")  # 15 bytes
    with pytest.raises(MasterKeyError, match="at least 16 bytes"):
        derive_master_key("valid-secret", salt="not_bytes")  # type: ignore[arg-type]


def test_kek_generation_produces_32_byte_key():
    """4. Generate random 256-bit KEKs."""
    kek1 = generate_kek()
    kek2 = generate_kek()
    assert isinstance(kek1, bytes)
    assert len(kek1) == 32
    assert isinstance(kek2, bytes)
    assert len(kek2) == 32
    assert kek1 != kek2


def test_kek_protect_unprotect_roundtrip():
    """5. KEK protect and unprotect roundtrip returns the original key."""
    master_key, _ = derive_master_key("test-master-secret")
    kek = generate_kek()
    version = 1
    protected = protect_kek(kek, master_key, version)

    assert isinstance(protected, ProtectedKEK)
    assert isinstance(protected.encrypted_kek, bytes)
    assert protected.encrypted_kek != kek
    assert len(protected.nonce) == 12
    assert len(protected.salt) == 16

    unprotected = unprotect_kek(protected, master_key, version)
    assert unprotected == kek


def test_kek_unprotect_fails_with_wrong_master_key():
    """6. KEK unprotect fails with KEKProtectionError when using a different master key."""
    master_key1, _ = derive_master_key("secret-one")
    master_key2, _ = derive_master_key("secret-two")
    kek = generate_kek()
    protected = protect_kek(kek, master_key1, kek_version=1)

    with pytest.raises(KEKProtectionError, match="authentication failed"):
        unprotect_kek(protected, master_key2, kek_version=1)


def test_kek_unprotect_fails_with_wrong_version():
    """7. KEK unprotect fails with KEKProtectionError if kek_version AAD does not match."""
    master_key, _ = derive_master_key("test-master-secret")
    kek = generate_kek()
    protected = protect_kek(kek, master_key, kek_version=1)

    with pytest.raises(KEKProtectionError, match="authentication failed"):
        unprotect_kek(protected, master_key, kek_version=2)


def test_kek_unprotect_fails_with_tampered_ciphertext():
    """8. KEK unprotect fails with KEKProtectionError if encrypted payload or nonce is altered."""
    master_key, _ = derive_master_key("test-master-secret")
    kek = generate_kek()
    protected = protect_kek(kek, master_key, kek_version=1)

    # Tamper with encrypted ciphertext
    tampered_ct = bytearray(protected.encrypted_kek)
    tampered_ct[0] ^= 0xFF
    tampered_prot_ct = ProtectedKEK(bytes(tampered_ct), protected.nonce, protected.salt)
    with pytest.raises(KEKProtectionError, match="authentication failed"):
        unprotect_kek(tampered_prot_ct, master_key, kek_version=1)

    # Tamper with nonce
    tampered_nonce = bytearray(protected.nonce)
    tampered_nonce[0] ^= 0xFF
    tampered_prot_nonce = ProtectedKEK(protected.encrypted_kek, bytes(tampered_nonce), protected.salt)
    with pytest.raises(KEKProtectionError, match="authentication failed"):
        unprotect_kek(tampered_prot_nonce, master_key, kek_version=1)


def test_dek_generation_produces_32_byte_key():
    """9. Generate random 256-bit DEKs."""
    dek1 = generate_dek()
    dek2 = generate_dek()
    assert isinstance(dek1, bytes)
    assert len(dek1) == 32
    assert isinstance(dek2, bytes)
    assert len(dek2) == 32
    assert dek1 != dek2


def test_dek_wrap_unwrap_roundtrip():
    """10. DEK wrap and unwrap roundtrip returns original key."""
    kek = generate_kek()
    dek = generate_dek()
    file_id = 42
    wrapped = wrap_dek(dek, kek, file_id)

    assert isinstance(wrapped, WrappedDEK)
    assert isinstance(wrapped.wrapped_dek, bytes)
    assert wrapped.wrapped_dek != dek
    assert len(wrapped.nonce) == 12

    unwrapped = unwrap_dek(wrapped, kek, file_id)
    assert unwrapped == dek


def test_dek_unwrap_fails_with_wrong_kek():
    """11. DEK unwrap fails with DEKWrapError if wrong KEK is supplied."""
    kek1 = generate_kek()
    kek2 = generate_kek()
    dek = generate_dek()
    wrapped = wrap_dek(dek, kek1, file_id=42)

    with pytest.raises(DEKWrapError, match="authentication failed"):
        unwrap_dek(wrapped, kek2, file_id=42)


def test_dek_unwrap_fails_with_wrong_file_id():
    """12. DEK unwrap fails with DEKWrapError if file_id AAD differs."""
    kek = generate_kek()
    dek = generate_dek()
    wrapped = wrap_dek(dek, kek, file_id=42)

    with pytest.raises(DEKWrapError, match="authentication failed"):
        unwrap_dek(wrapped, kek, file_id=99)


def test_dek_rewrap_produces_valid_wrapped_dek():
    """13. Re-wrapping DEK from old to new KEK allows unwrapping with new KEK only."""
    old_kek = generate_kek()
    new_kek = generate_kek()
    dek = generate_dek()
    file_id = 101

    wrapped_old = wrap_dek(dek, old_kek, file_id)
    wrapped_new = rewrap_dek(wrapped_old, old_kek, new_kek, file_id)

    assert isinstance(wrapped_new, WrappedDEK)
    assert unwrap_dek(wrapped_new, new_kek, file_id) == dek
    with pytest.raises(DEKWrapError):
        unwrap_dek(wrapped_new, old_kek, file_id)


def test_envelope_encrypt_decrypt_roundtrip():
    """14. Envelope encrypt and decrypt roundtrip preserves plaintext."""
    dek = generate_dek()
    file_id = 15
    plaintext = b"Sensitive document content for envelope encryption"

    nonce, ciphertext = envelope_encrypt(plaintext, dek, file_id)
    assert len(nonce) == 12
    assert ciphertext != plaintext

    decrypted = envelope_decrypt(nonce, ciphertext, dek, file_id)
    assert decrypted == plaintext

    # With optional additional authenticated data (AAD)
    custom_aad = b"file_metadata:owner=1|mime=text/plain"
    nonce_aad, ct_aad = envelope_encrypt(plaintext, dek, file_id, aad=custom_aad)
    decrypted_aad = envelope_decrypt(nonce_aad, ct_aad, dek, file_id, aad=custom_aad)
    assert decrypted_aad == plaintext


def test_envelope_decrypt_fails_with_wrong_dek():
    """15. Envelope decrypt fails with DEKWrapError if decrypted with wrong DEK."""
    dek1 = generate_dek()
    dek2 = generate_dek()
    file_id = 15
    nonce, ciphertext = envelope_encrypt(b"Payload to encrypt", dek1, file_id)

    with pytest.raises(DEKWrapError, match="Envelope decryption failed"):
        envelope_decrypt(nonce, ciphertext, dek2, file_id)


def test_envelope_decrypt_fails_with_tampered_ciphertext():
    """16. Envelope decrypt fails with DEKWrapError if ciphertext, nonce, or AAD is modified."""
    dek = generate_dek()
    file_id = 15
    nonce, ciphertext = envelope_encrypt(b"Payload to be tampered", dek, file_id)

    # Flip byte in ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01
    with pytest.raises(DEKWrapError, match="Envelope decryption failed"):
        envelope_decrypt(nonce, bytes(tampered_ct), dek, file_id)

    # Flip byte in nonce
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0x01
    with pytest.raises(DEKWrapError, match="Envelope decryption failed"):
        envelope_decrypt(bytes(tampered_nonce), ciphertext, dek, file_id)

    # Wrong file_id (bound in combined AAD)
    with pytest.raises(DEKWrapError, match="Envelope decryption failed"):
        envelope_decrypt(nonce, ciphertext, dek, file_id=999)

    # Wrong extra AAD
    with pytest.raises(DEKWrapError, match="Envelope decryption failed"):
        envelope_decrypt(nonce, ciphertext, dek, file_id, aad=b"mismatched-aad")


# ---------------------------------------------------------------------------
# Section 2: Service Layer Tests (requires Flask app context)
# ---------------------------------------------------------------------------

def test_ensure_kms_initialized_creates_active_kek(app):
    """17. After initialization, get_active_kek returns a valid 32-byte active KEK."""
    with app.app_context():
        kek, version = get_active_kek()
        assert isinstance(kek, bytes)
        assert len(kek) == 32
        assert version == 1

        active_row = get_active_kek_row()
        assert active_row is not None
        assert active_row["status"] == "active"
        assert active_row["version"] == 1

        status = get_kms_status()
        assert status["initialized"] is True
        assert status["active_kek_version"] == 1


def test_ensure_kms_initialized_idempotent(app):
    """18. Calling ensure_kms_initialized multiple times does not recreate the KEK."""
    with app.app_context():
        res = ensure_kms_initialized()
        assert res["status"] == "already_initialized"
        assert res["active_version"] == 1

        _, active_v = get_active_kek()
        assert active_v == 1


def test_create_kek_demotes_previous_active(app):
    """19. create_kek demotes the current active key to 'rotated' and activates the new key."""
    with app.app_context():
        _, old_version = get_active_kek()
        new_meta = create_kek(description="Second version")
        assert new_meta["version"] == old_version + 1
        assert new_meta["status"] == "active"

        # Previous active KEK is now 'rotated'
        _, old_meta = get_kek_by_version(old_version)
        assert old_meta["status"] == "rotated"
        assert old_meta["rotated_at"] is not None

        # Newly created key is now active
        _, active_v = get_active_kek()
        assert active_v == new_meta["version"]


def test_rotate_kek_creates_new_version(app):
    """20. rotate_kek creates a new version > old version and sets old version to 'rotated'."""
    with app.app_context():
        _, initial_v = get_active_kek()
        result = rotate_kek(description="Manual rotation test")
        assert result["version"] == initial_v + 1
        assert result["status"] == "active"

        _, active_v = get_active_kek()
        assert active_v == result["version"]

        _, old_meta = get_kek_by_version(initial_v)
        assert old_meta["status"] == "rotated"


def test_list_kek_versions_returns_all(app):
    """21. list_kek_versions returns metadata for all KEK versions ordered descending."""
    with app.app_context():
        rotate_kek(description="Rotation 1")
        rotate_kek(description="Rotation 2")

        versions = list_kek_versions()
        assert len(versions) >= 3
        version_numbers = [item["version"] for item in versions]
        assert 1 in version_numbers and 2 in version_numbers and 3 in version_numbers
        assert version_numbers == sorted(version_numbers, reverse=True)

        for v_dict in versions:
            assert "version" in v_dict
            assert "status" in v_dict
            assert "created_at" in v_dict
            assert "dek_count" in v_dict


def test_get_kek_by_version_returns_correct_key(app):
    """22. get_kek_by_version retrieves historical key that successfully decrypts its DEKs."""
    with app.app_context():
        file_id = _create_dummy_file(app)
        dek = generate_dek()
        reg = register_dek(file_id, dek)
        v1 = reg["kek_version"]

        # Rotate away from v1
        rotate_kek(description="Rotation test")

        kek1, meta1 = get_kek_by_version(v1)
        assert meta1["version"] == v1
        assert meta1["status"] == "rotated"

        # Verify retrieved KEK unprotects the DEK correctly
        db = get_db()
        row = db.execute("SELECT wrapped_dek, nonce FROM dek_registry WHERE file_id = ?", (file_id,)).fetchone()
        wrapped = WrappedDEK(wrapped_dek=bytes(row["wrapped_dek"]), nonce=bytes(row["nonce"]))
        unwrapped = unwrap_dek(wrapped, kek1, file_id)
        assert unwrapped == dek


def test_get_kek_by_version_not_found_raises(app):
    """23. get_kek_by_version raises KEKNotFoundError for nonexistent version."""
    with app.app_context():
        with pytest.raises(KEKNotFoundError, match="not found"):
            get_kek_by_version(999999)


def test_compromise_active_kek_auto_creates_new(app):
    """24. Compromising the active KEK automatically generates a new active KEK."""
    with app.app_context():
        _, v1 = get_active_kek()
        result = compromise_kek(v1, reason="Test drill")
        assert result["status"] == "compromised"
        assert result["compromised_at"] is not None
        assert "new_active_version" in result
        new_v = result["new_active_version"]
        assert new_v > v1

        _, active_v = get_active_kek()
        assert active_v == new_v

        _, old_meta = get_kek_by_version(v1)
        assert old_meta["status"] == "compromised"


def test_compromise_already_compromised_raises(app):
    """25. Compromising an already-compromised KEK raises KMSError."""
    with app.app_context():
        _, v1 = get_active_kek()
        compromise_kek(v1)
        with pytest.raises(KMSError, match="already marked as compromised"):
            compromise_kek(v1)


def test_recover_blocked_while_deks_reference_key(app):
    """26. recover_from_compromise fails with KMSError if DEKs are still wrapped by the key."""
    with app.app_context():
        file_id = _create_dummy_file(app)
        dek = generate_dek()
        reg = register_dek(file_id, dek)
        v1 = reg["kek_version"]

        compromise_kek(v1, reason="Incident test")
        with pytest.raises(KMSError) as exc_info:
            recover_from_compromise(v1)
        assert "DEK(s) still wrapped by this key" in str(exc_info.value)


def test_recover_succeeds_after_rewrap(app):
    """27. After rewrapping all DEKs away, recover_from_compromise changes status to 'rotated'."""
    with app.app_context():
        file_id = _create_dummy_file(app)
        dek = generate_dek()
        reg = register_dek(file_id, dek)
        v1 = reg["kek_version"]

        compromise_kek(v1, reason="Incident test")
        rewrap_summary = rewrap_all_deks()
        assert rewrap_summary["rewrapped"] >= 1

        recovered = recover_from_compromise(v1)
        assert recovered["status"] == "rotated"


def test_destroy_active_kek_raises(app):
    """28. Attempting to destroy the active KEK raises KMSError."""
    with app.app_context():
        _, active_v = get_active_kek()
        with pytest.raises(KMSError, match="Cannot destroy the active KEK"):
            destroy_kek(active_v)


def test_destroy_with_deks_raises(app):
    """29. Attempting to destroy a KEK that still has wrapped DEKs raises KMSError."""
    with app.app_context():
        file_id = _create_dummy_file(app)
        dek = generate_dek()
        reg = register_dek(file_id, dek)
        v1 = reg["kek_version"]

        rotate_kek(description="Rotate away from v1")
        with pytest.raises(KMSError) as exc_info:
            destroy_kek(v1)
        assert "DEK(s) still wrapped by this key" in str(exc_info.value)


def test_destroy_clean_key_succeeds(app):
    """30. Destroying a KEK with 0 referencing DEKs succeeds and marks it 'destroyed'."""
    with app.app_context():
        # Rotate so v1 has 0 DEKs and is rotated
        rotate_kek(description="Rotate away from v1")
        destroyed = destroy_kek(1)
        assert destroyed["status"] == "destroyed"
        assert destroyed["destroyed_at"] is not None

        # Using destroyed key raises KMSError
        with pytest.raises(KMSError, match="destroyed and cannot be used"):
            get_kek_by_version(1)

        # Destroying an already destroyed key raises KMSError
        with pytest.raises(KMSError, match="already destroyed"):
            destroy_kek(1)


def test_register_and_retrieve_dek(app):
    """31. register_dek stores wrapped DEK, and get_dek_for_file returns the exact plaintext DEK."""
    with app.app_context():
        file_id = _create_dummy_file(app)
        dek = generate_dek()
        reg = register_dek(file_id, dek)
        assert reg["file_id"] == file_id
        assert reg["status"] == "wrapped"

        retrieved_dek, kek_v = get_dek_for_file(file_id)
        assert retrieved_dek == dek
        assert kek_v == reg["kek_version"]

        info = get_dek_info(file_id)
        assert info is not None
        assert info["file_id"] == file_id
        assert info["kek_version"] == kek_v
        assert info["kek_status"] == "active"


def test_get_dek_for_missing_file_raises(app):
    """32. get_dek_for_file raises KMSError when file has no registered DEK."""
    with app.app_context():
        with pytest.raises(KMSError, match="No DEK registered"):
            get_dek_for_file(999999)


def test_rewrap_all_deks_moves_to_active_kek(app):
    """33. rewrap_all_deks re-wraps all existing DEKs under the latest active KEK."""
    with app.app_context():
        f1 = _create_dummy_file(app, filename="doc1.txt")
        f2 = _create_dummy_file(app, filename="doc2.txt")
        dek1 = generate_dek()
        dek2 = generate_dek()

        register_dek(f1, dek1)
        register_dek(f2, dek2)

        rotate_kek(description="Rotate to v2")
        _, active_v = get_active_kek()

        summary = rewrap_all_deks()
        assert summary["total"] == 2
        assert summary["rewrapped"] == 2
        assert summary["failed"] == 0

        d1, v1 = get_dek_for_file(f1)
        d2, v2 = get_dek_for_file(f2)
        assert d1 == dek1
        assert d2 == dek2
        assert v1 == active_v
        assert v2 == active_v


def test_rotation_policy_crud(app):
    """34. Retrieve default rotation policy, update it, and verify changes persist."""
    with app.app_context():
        default_policy = get_rotation_policy()
        assert default_policy["key_type"] == "kek"
        assert default_policy["rotation_interval_days"] == 90
        assert default_policy["auto_rotate"] is False
        assert default_policy["max_versions"] == 10

        updated = update_rotation_policy(
            rotation_interval_days=45,
            auto_rotate=True,
            max_versions=25,
        )
        assert updated["rotation_interval_days"] == 45
        assert updated["auto_rotate"] is True
        assert updated["max_versions"] == 25

        persisted = get_rotation_policy()
        assert persisted["rotation_interval_days"] == 45
        assert persisted["auto_rotate"] is True
        assert persisted["max_versions"] == 25


def test_policy_validation_rejects_bad_values(app):
    """35. update_rotation_policy raises PolicyViolationError for invalid parameters."""
    with app.app_context():
        with pytest.raises(PolicyViolationError, match="at least 1 day"):
            update_rotation_policy(rotation_interval_days=0)
        with pytest.raises(PolicyViolationError, match="must not exceed 365 days"):
            update_rotation_policy(rotation_interval_days=366)
        with pytest.raises(PolicyViolationError, match="at least 2 key versions"):
            update_rotation_policy(max_versions=1)
        with pytest.raises(PolicyViolationError, match="more than 100 versions"):
            update_rotation_policy(max_versions=101)


def test_check_rotation_needed_fresh_key(app):
    """36. check_rotation_needed returns False for a newly initialized KEK."""
    with app.app_context():
        check = check_rotation_needed()
        assert check["rotation_needed"] is False
        assert check["reason"] is None

        # perform_auto_rotation returns None when rotation is not needed
        res = perform_auto_rotation()
        assert res is None


def test_audit_log_records_events(app):
    """37. KMS operations record audit log entries with appropriate actions."""
    with app.app_context():
        log_kms_event(
            action="custom_audit_test",
            kek_version=1,
            detail="Testing custom audit log",
        )
        entries, total = list_kms_audit(limit=100)
        assert total > 0
        actions = [entry["action"] for entry in entries]
        assert "custom_audit_test" in actions
        assert "kek_created" in actions

        filtered, count = list_kms_audit(action_filter="custom_audit_test")
        assert count >= 1
        assert all(entry["action"] == "custom_audit_test" for entry in filtered)


# ---------------------------------------------------------------------------
# Section 3: API Layer Tests (requires Flask test client)
# ---------------------------------------------------------------------------

def test_api_status_unauthenticated_returns_401(client):
    """38. GET /api/kms/status without authentication returns 401."""
    resp = client.get("/api/kms/status")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Authentication required"


def test_api_status_non_admin_returns_403(app, client):
    """39. GET /api/kms/status with a regular user returns 403."""
    _create_user_session(app, client)
    resp = client.get("/api/kms/status")
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Admin access required"


def test_api_status_admin_returns_200(app, client):
    """40. GET /api/kms/status with an admin returns 200 with KMS status payload."""
    _create_admin_session(app, client)
    resp = client.get("/api/kms/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "kms" in data
    assert data["kms"]["initialized"] is True
    assert data["kms"]["active_kek_version"] >= 1
    assert "policy" in data["kms"]


def test_api_keys_list_returns_keys(app, client):
    """41. GET /api/kms/keys returns the list of KEK versions; POST creates a new KEK."""
    _create_admin_session(app, client)
    resp = client.get("/api/kms/keys")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "keys" in data
    assert data["total"] >= 1
    assert any(k["status"] == "active" for k in data["keys"])

    # Create new key via POST /api/kms/keys
    create_resp = client.post("/api/kms/keys", json={"description": "API created key"})
    assert create_resp.status_code == 201
    created_key = create_resp.get_json()["key"]
    assert created_key["version"] >= 2
    assert created_key["status"] == "active"

    # Get single key metadata via GET /api/kms/keys/<version>
    get_resp = client.get(f"/api/kms/keys/{created_key['version']}")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["key"]["version"] == created_key["version"]


def test_api_rotate_creates_new_key(app, client):
    """42. POST /api/kms/rotate triggers KEK rotation and returns 201 with new key metadata."""
    _create_admin_session(app, client)
    resp = client.post("/api/kms/rotate", json={"description": "Admin rotation test"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert "key" in data
    assert data["key"]["status"] == "active"
    assert data["key"]["version"] >= 2


def test_api_rewrap_returns_result(app, client):
    """43. POST /api/kms/rewrap initiates DEK rewrapping and returns 200 with batch summary."""
    _create_admin_session(app, client)
    resp = client.post("/api/kms/rewrap", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "result" in data
    assert "rewrapped" in data["result"]
    assert "total" in data["result"]
    assert "failed" in data["result"]


def test_api_compromise_marks_key(app, client):
    """44. POST /api/kms/keys/<version>/compromise marks the KEK as compromised."""
    _create_admin_session(app, client)
    resp = client.post("/api/kms/keys/1/compromise", json={"reason": "Security audit test"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["key"]["status"] == "compromised"
    assert "new_active_version" in data["key"]


def test_api_recover_after_rewrap(app, client):
    """45. POST /api/kms/keys/<version>/recover recovers compromised key after DEKs are rewrapped."""
    _create_admin_session(app, client)
    # Key 1 has 0 DEKs. Mark it compromised (auto-creates v2 as active)
    client.post("/api/kms/keys/1/compromise", json={"reason": "Incident recovery drill"})
    # Rewrap any DEKs
    rewrap_resp = client.post("/api/kms/rewrap", json={})
    assert rewrap_resp.status_code == 200

    # Recover key 1
    resp = client.post("/api/kms/keys/1/recover", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["key"]["status"] == "rotated"


def test_api_destroy_clean_key(app, client):
    """46. POST /api/kms/keys/<version>/destroy permanently destroys an unreferenced historical key."""
    _create_admin_session(app, client)
    # Rotate first so key 1 is not active and has 0 DEKs
    client.post("/api/kms/rotate", json={"description": "Rotate away from v1"})
    resp = client.post("/api/kms/keys/1/destroy", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["key"]["status"] == "destroyed"

    # Verifying GET key 1 returns 400 since it is destroyed
    get_resp = client.get("/api/kms/keys/1")
    assert get_resp.status_code == 400
    assert "destroyed" in get_resp.get_json()["error"]


def test_api_policy_get_and_update(app, client):
    """47. GET /api/kms/policy and PUT /api/kms/policy manage the rotation policy configuration."""
    _create_admin_session(app, client)
    get_resp = client.get("/api/kms/policy")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["policy"]["key_type"] == "kek"

    put_resp = client.put("/api/kms/policy", json={
        "rotation_interval_days": 60,
        "auto_rotate": True,
        "max_versions": 8,
    })
    assert put_resp.status_code == 200
    policy = put_resp.get_json()["policy"]
    assert policy["rotation_interval_days"] == 60
    assert policy["auto_rotate"] is True
    assert policy["max_versions"] == 8

    # Reject invalid update
    bad_resp = client.put("/api/kms/policy", json={"rotation_interval_days": 0})
    assert bad_resp.status_code == 400
    assert "error" in bad_resp.get_json()


def test_api_audit_returns_entries(app, client):
    """48. GET /api/kms/audit returns audit log entries and supports action filtering."""
    _create_admin_session(app, client)
    resp = client.get("/api/kms/audit")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "entries" in data
    assert data["total"] >= 1

    # Test filtering by action
    filter_resp = client.get("/api/kms/audit?action=kek_created")
    assert filter_resp.status_code == 200
    assert filter_resp.get_json()["total"] >= 1
    assert all(entry["action"] == "kek_created" for entry in filter_resp.get_json()["entries"])


# ---------------------------------------------------------------------------
# Extra API endpoints coverage (rotation-check, dek-info, initialize)
# ---------------------------------------------------------------------------

def test_api_rotation_check_endpoint(app, client):
    """Verify GET /api/kms/rotation-check returns policy evaluation status."""
    _create_admin_session(app, client)
    resp = client.get("/api/kms/rotation-check")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "rotation_check" in data
    assert data["rotation_check"]["rotation_needed"] is False


def test_api_dek_info_endpoint(app, client):
    """Verify GET /api/kms/dek/<file_id> returns DEK metadata or 404."""
    _create_admin_session(app, client)
    file_id = _create_dummy_file(app)
    with app.app_context():
        register_dek(file_id, generate_dek())

    resp = client.get(f"/api/kms/dek/{file_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "dek" in data
    assert data["dek"]["file_id"] == file_id

    missing_resp = client.get("/api/kms/dek/999999")
    assert missing_resp.status_code == 404


def test_api_initialize_endpoint(app, client):
    """Verify POST /api/kms/initialize ensures active KEK exists."""
    _create_admin_session(app, client)
    resp = client.post("/api/kms/initialize")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "result" in data
    assert data["result"]["status"] in ("initialized", "already_initialized")
