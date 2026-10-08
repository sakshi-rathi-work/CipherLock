"""Authenticated, versioned protection for user RSA private keys."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.aes import AES_KEY_SIZE, AES_NONCE_SIZE
from crypto.rsa import KeyFormatError, load_private_key, private_key_to_pem

_MAGIC = b"CLPK"
_VERSION = 1
_HEADER = _MAGIC + bytes((_VERSION,))
_SALT_SIZE = 16
_NONCE_SIZE = AES_NONCE_SIZE
_TAG_SIZE = 16
_INFO = b"CipherLock user private-key protection v1"
_MIN_SECRET_SIZE = 32


class PrivateKeyProtectionError(Exception):
    """Raised when a protected private key cannot be authenticated or loaded."""


def _derive_key(secret: str | bytes, salt: bytes) -> bytes:
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        secret_bytes = secret
    else:
        raise TypeError("Private-key protection secret must be str or bytes.")
    if len(secret_bytes) < _MIN_SECRET_SIZE:
        raise ValueError("Private-key protection secret must contain at least 32 bytes.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=_INFO,
    ).derive(secret_bytes)


def _associated_data(user_id: int) -> bytes:
    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
        raise ValueError("A positive integer user ID is required.")
    try:
        return _HEADER + user_id.to_bytes(8, byteorder="big")
    except OverflowError:
        raise ValueError("User ID is outside the supported range.") from None


def protect_private_key(
    private_key: RSAPrivateKey,
    secret: str | bytes,
    user_id: int,
) -> bytes:
    """Encrypt a PKCS#8 private key into a versioned binary envelope.

    The envelope contains the format version, a random HKDF salt, a fresh
    AES-GCM nonce, and ciphertext concatenated with its authentication tag.
    """
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("An RSA private key is required.")

    associated_data = _associated_data(user_id)
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    key = _derive_key(secret, salt)
    private_pem = private_key_to_pem(private_key)
    ciphertext = AESGCM(key).encrypt(nonce, private_pem, associated_data)
    return _HEADER + salt + nonce + ciphertext


def unprotect_private_key(
    protected_key: bytes,
    secret: str | bytes,
    user_id: int,
) -> RSAPrivateKey:
    """Authenticate, decrypt, and load a protected PKCS#8 RSA private key."""
    if not isinstance(protected_key, bytes):
        raise TypeError("Protected private key must be bytes.")

    minimum_size = len(_HEADER) + _SALT_SIZE + _NONCE_SIZE + _TAG_SIZE
    if len(protected_key) < minimum_size or protected_key[:len(_HEADER)] != _HEADER:
        raise PrivateKeyProtectionError("Invalid protected private-key envelope.")

    offset = len(_HEADER)
    salt = protected_key[offset:offset + _SALT_SIZE]
    offset += _SALT_SIZE
    nonce = protected_key[offset:offset + _NONCE_SIZE]
    offset += _NONCE_SIZE
    ciphertext = protected_key[offset:]

    associated_data = _associated_data(user_id)
    key = _derive_key(secret, salt)
    try:
        private_pem = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise PrivateKeyProtectionError(
            "Protected private key could not be authenticated."
        ) from None

    try:
        loaded_key = load_private_key(private_pem)
    except (KeyFormatError, TypeError, ValueError):
        raise PrivateKeyProtectionError("Protected private key is invalid.") from None
    return loaded_key
