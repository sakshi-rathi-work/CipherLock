"""Unit tests for RSA-OAEP session key wrapping and unwrapping."""

import pytest

from crypto.aes import generate_session_key
from crypto.rsa import (
    UnwrapError,
    generate_rsa_keypair,
    unwrap_session_key,
    wrap_session_key,
)


def test_wrap_unwrap_happy_path():
    """Verify that a 32-byte AES session key wrapped with RSA-OAEP can be unwrapped by the recipient."""
    priv_a, pub_a = generate_rsa_keypair(bits=3072)
    session_key = generate_session_key()

    wrapped = wrap_session_key(pub_a, session_key)
    assert len(wrapped) == 384, "RSA-3072 wrapped key length must be exactly 384 bytes"

    unwrapped = unwrap_session_key(priv_a, wrapped)
    assert unwrapped == session_key


def test_wrap_invalid_key_length_rejected():
    """Verify that attempting to wrap session keys that are not 32 bytes is rejected."""
    _, pub = generate_rsa_keypair(bits=3072)

    invalid_lengths = [b"", b"123456789012345", b"A" * 16, b"B" * 31, b"C" * 33, b"D" * 64]
    for bad_key in invalid_lengths:
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            wrap_session_key(pub, bad_key)


def test_wrap_type_checking():
    """Verify type checking for public key and key parameters in wrap_session_key."""
    priv, pub = generate_rsa_keypair(bits=3072)
    session_key = generate_session_key()

    with pytest.raises(TypeError, match="RSA public key is required"):
        wrap_session_key(priv, session_key)  # passing private key instead of public key

    with pytest.raises(TypeError, match="AES session key must be bytes"):
        wrap_session_key(pub, "not-bytes")


def test_unwrap_wrong_private_key_fails():
    """Verify that unwrapping with a non-matching private key raises UnwrapError."""
    _, pub_a = generate_rsa_keypair(bits=3072)
    priv_b, _ = generate_rsa_keypair(bits=3072)

    session_key = generate_session_key()
    wrapped = wrap_session_key(pub_a, session_key)

    with pytest.raises(UnwrapError, match="could not be decrypted|invalid"):
        unwrap_session_key(priv_b, wrapped)


def test_unwrap_corrupted_ciphertext_fails():
    """Verify that unwrapping corrupted bytes or wrong lengths raises UnwrapError."""
    priv, pub = generate_rsa_keypair(bits=3072)
    session_key = generate_session_key()
    wrapped = wrap_session_key(pub, session_key)

    # Flip one byte in valid wrapped payload
    corrupted = bytearray(wrapped)
    corrupted[10] ^= 0xFF
    with pytest.raises(UnwrapError, match="could not be decrypted"):
        unwrap_session_key(priv, bytes(corrupted))

    # Invalid length wrapped payloads
    with pytest.raises(UnwrapError, match="invalid"):
        unwrap_session_key(priv, b"too_short")

    with pytest.raises(UnwrapError, match="invalid"):
        unwrap_session_key(priv, wrapped + b"extra")


def test_unwrap_type_checking():
    """Verify type checking for parameters in unwrap_session_key."""
    priv, pub = generate_rsa_keypair(bits=3072)
    session_key = generate_session_key()
    wrapped = wrap_session_key(pub, session_key)

    with pytest.raises(TypeError, match="RSA private key is required"):
        unwrap_session_key(pub, wrapped)  # passing public key instead of private key

    with pytest.raises(TypeError, match="wrapped session key must be bytes"):
        unwrap_session_key(priv, "not-bytes")


def test_oaep_randomization():
    """Verify that RSA-OAEP wrapping is randomized (same key wrapped twice produces different ciphertexts)."""
    _, pub = generate_rsa_keypair(bits=3072)
    priv, _ = generate_rsa_keypair(bits=3072)
    # Re-use priv for pub matching
    priv_match, pub_match = generate_rsa_keypair(bits=3072)

    session_key = generate_session_key()

    wrapped1 = wrap_session_key(pub_match, session_key)
    wrapped2 = wrap_session_key(pub_match, session_key)

    assert wrapped1 != wrapped2, "RSA-OAEP must produce distinct ciphertexts for identical inputs"
    assert len(wrapped1) == 384
    assert len(wrapped2) == 384

    # Both must unwrap to identical original key
    assert unwrap_session_key(priv_match, wrapped1) == session_key
    assert unwrap_session_key(priv_match, wrapped2) == session_key
