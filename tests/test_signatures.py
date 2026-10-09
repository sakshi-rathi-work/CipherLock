"""Unit tests for RSA-PSS digital signatures and SHA-256 hashing."""

import hashlib
import pytest

from crypto.rsa import generate_rsa_keypair
from crypto.signatures import sha256_hex, sign_data, verify_signature


def test_signature_sign_verify_happy_path():
    """Verify that a message signed with RSA-PSS can be verified with the matching public key."""
    priv, pub = generate_rsa_keypair(bits=3072)
    message = b"CipherLock RSA-PSS signature test payload"

    signature = sign_data(priv, message)
    assert isinstance(signature, bytes)
    assert len(signature) == 384, "RSA-3072 signature length must be 384 bytes"

    is_valid = verify_signature(pub, message, signature)
    assert is_valid is True


def test_signature_bit_flip_in_message_rejected():
    """Verify that altering even a single bit in the signed message causes verification to fail."""
    priv, pub = generate_rsa_keypair(bits=3072)
    message = b"Confidential financial statement: $10,000"
    signature = sign_data(priv, message)

    # Tampered message
    tampered_message = b"Confidential financial statement: $90,000"
    assert verify_signature(pub, tampered_message, signature) is False


def test_signature_corrupted_signature_bytes_rejected():
    """Verify that altering bytes in the signature payload causes verification to fail (returns False)."""
    priv, pub = generate_rsa_keypair(bits=3072)
    message = b"Authentic system command"
    signature = sign_data(priv, message)

    corrupted_sig = bytearray(signature)
    corrupted_sig[15] ^= 0x01
    assert verify_signature(pub, message, bytes(corrupted_sig)) is False

    # Truncated or wrong length signatures
    assert verify_signature(pub, message, b"too_short") is False
    assert verify_signature(pub, message, signature + b"extra") is False


def test_signature_wrong_public_key_rejected():
    """Verify that a signature made by User A is rejected when verified with User B's public key."""
    priv_a, pub_a = generate_rsa_keypair(bits=3072)
    priv_b, pub_b = generate_rsa_keypair(bits=3072)

    message = b"Message sent by User A"
    sig_a = sign_data(priv_a, message)

    assert verify_signature(pub_a, message, sig_a) is True
    assert verify_signature(pub_b, message, sig_a) is False


def test_signature_empty_and_large_data():
    """Verify that signing empty data and large payloads works correctly."""
    priv, pub = generate_rsa_keypair(bits=3072)

    # Empty payload
    empty_data = b""
    sig_empty = sign_data(priv, empty_data)
    assert verify_signature(pub, empty_data, sig_empty) is True

    # 1 MB large payload
    large_data = b"X" * (1024 * 1024)
    sig_large = sign_data(priv, large_data)
    assert verify_signature(pub, large_data, sig_large) is True


def test_pss_signature_randomization():
    """Verify RSA-PSS probabilistic signature property (same message yields different signatures, both valid)."""
    priv, pub = generate_rsa_keypair(bits=3072)
    message = b"Deterministic messages still produce randomized PSS signatures"

    sig1 = sign_data(priv, message)
    sig2 = sign_data(priv, message)

    assert sig1 != sig2, "RSA-PSS must produce randomized signatures due to salt"
    assert verify_signature(pub, message, sig1) is True
    assert verify_signature(pub, message, sig2) is True


def test_sha256_hex_utility():
    """Verify the SHA-256 hexadecimal digest helper function against standard test vectors."""
    # Empty string hash
    empty_hash = sha256_hex(b"")
    assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Known string hash
    data = b"CipherLock"
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_hex(data) == expected
    assert len(sha256_hex(data)) == 64


def test_signatures_type_checking():
    """Verify proper type validation for sign_data, verify_signature, and sha256_hex."""
    priv, pub = generate_rsa_keypair(bits=3072)
    message = b"Sample text"
    sig = sign_data(priv, message)

    with pytest.raises(TypeError, match="RSA private key is required"):
        sign_data(pub, message)  # passing public key instead of private key

    with pytest.raises(TypeError, match="Data to sign must be bytes"):
        sign_data(priv, "not-bytes")

    with pytest.raises(TypeError, match="RSA public key is required"):
        verify_signature(priv, message, sig)

    with pytest.raises(TypeError, match="Data to verify must be bytes"):
        verify_signature(pub, "not-bytes", sig)

    with pytest.raises(TypeError, match="Signature must be bytes"):
        verify_signature(pub, message, "not-bytes")

    with pytest.raises(TypeError, match="Input data must be bytes"):
        sha256_hex("not-bytes")
