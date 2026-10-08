"""AES-256-GCM primitives used by CipherLock."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16


class DecryptionError(Exception):
    """Raised when AES-GCM authentication fails."""


def generate_session_key() -> bytes:
    """Generate a fresh 256-bit AES key using the cryptographic backend."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """Encrypt bytes, returning a fresh 12-byte nonce and ciphertext with tag."""
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
        raise TypeError("Plaintext and additional authenticated data must be bytes.")

    nonce = os.urandom(AES_NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_bytes(
    key: bytes,
    nonce: bytes,
    data: bytes,
    aad: bytes = b"",
) -> bytes:
    """Authenticate and decrypt ciphertext concatenated with its 16-byte tag."""
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if not isinstance(nonce, bytes) or len(nonce) != AES_NONCE_SIZE:
        raise ValueError("AES-256-GCM requires a 12-byte nonce.")
    if not isinstance(data, bytes) or len(data) < AES_TAG_SIZE:
        raise ValueError("AES-GCM ciphertext must include a 16-byte authentication tag.")
    if not isinstance(aad, bytes):
        raise TypeError("Additional authenticated data must be bytes.")

    try:
        return AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag:
        raise DecryptionError("AES-GCM authentication failed.") from None
