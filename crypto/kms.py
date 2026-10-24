"""Phase 10 – KMS cryptographic primitives for envelope encryption.

Key hierarchy (three tiers):

    Master Key  (derived from SECRET_KEY + dedicated salt via HKDF-SHA256)
        └── KEK  (Key Encryption Key – versioned, stored encrypted)
              └── DEK  (Data Encryption Key – per-file, wrapped by KEK)

All symmetric encryption uses AES-256-GCM with 12-byte nonces and 16-byte tags.
"""
from __future__ import annotations

import os
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.aes import AES_KEY_SIZE, AES_NONCE_SIZE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MASTER_KEY_INFO = b"CipherLock KMS master-key derivation v1"
_KEK_PROTECTION_INFO = b"CipherLock KMS KEK protection v1"
_DEK_WRAP_INFO = b"CipherLock KMS DEK wrap v1"
_MASTER_SALT_SIZE = 32
_KEK_SALT_SIZE = 16
_NONCE_SIZE = AES_NONCE_SIZE  # 12 bytes


class ProtectedKEK(NamedTuple):
    """Encrypted KEK envelope stored in the database."""
    encrypted_kek: bytes
    nonce: bytes
    salt: bytes


class WrappedDEK(NamedTuple):
    """Encrypted DEK envelope stored in the database."""
    wrapped_dek: bytes
    nonce: bytes


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KMSCryptoError(Exception):
    """Base for all KMS cryptographic failures."""


class MasterKeyError(KMSCryptoError):
    """Could not derive the master key."""


class KEKProtectionError(KMSCryptoError):
    """Could not protect or unprotect a KEK."""


class DEKWrapError(KMSCryptoError):
    """Could not wrap or unwrap a DEK."""


# ---------------------------------------------------------------------------
# Master key derivation
# ---------------------------------------------------------------------------

def derive_master_key(secret_key: str | bytes, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit master key from the application SECRET_KEY.

    Returns ``(master_key, salt)``.  When *salt* is None a fresh 32-byte
    random salt is generated.  The same salt must be reused to re-derive the
    identical master key.
    """
    if isinstance(secret_key, str):
        secret_bytes = secret_key.encode("utf-8")
    elif isinstance(secret_key, bytes):
        secret_bytes = secret_key
    else:
        raise MasterKeyError("SECRET_KEY must be str or bytes.")

    if not secret_bytes:
        raise MasterKeyError("SECRET_KEY must not be empty.")

    if salt is None:
        salt = os.urandom(_MASTER_SALT_SIZE)
    elif not isinstance(salt, bytes) or len(salt) < 16:
        raise MasterKeyError("Master key salt must be at least 16 bytes.")

    master_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=_MASTER_KEY_INFO,
    ).derive(secret_bytes)
    return master_key, salt


# ---------------------------------------------------------------------------
# KEK lifecycle
# ---------------------------------------------------------------------------

def generate_kek() -> bytes:
    """Generate a fresh 256-bit KEK."""
    return AESGCM.generate_key(bit_length=256)


def protect_kek(
    kek: bytes,
    master_key: bytes,
    kek_version: int,
) -> ProtectedKEK:
    """Encrypt a KEK under the master key with version-bound AAD.

    Returns a ``ProtectedKEK`` containing the encrypted KEK, nonce, and an
    independent HKDF salt so the per-KEK wrapping key is unique even if
    the master key is unchanged.
    """
    if not isinstance(kek, bytes) or len(kek) != AES_KEY_SIZE:
        raise KEKProtectionError("KEK must be a 32-byte key.")
    if not isinstance(master_key, bytes) or len(master_key) != AES_KEY_SIZE:
        raise KEKProtectionError("Master key must be a 32-byte key.")

    salt = os.urandom(_KEK_SALT_SIZE)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=_KEK_PROTECTION_INFO,
    ).derive(master_key)

    nonce = os.urandom(_NONCE_SIZE)
    aad = f"kek-version:{kek_version}".encode("utf-8")

    try:
        encrypted = AESGCM(wrapping_key).encrypt(nonce, kek, aad)
    except Exception as exc:
        raise KEKProtectionError("Failed to encrypt KEK.") from exc

    return ProtectedKEK(encrypted_kek=encrypted, nonce=nonce, salt=salt)


def unprotect_kek(
    protected: ProtectedKEK,
    master_key: bytes,
    kek_version: int,
) -> bytes:
    """Decrypt a stored KEK using the master key."""
    if not isinstance(master_key, bytes) or len(master_key) != AES_KEY_SIZE:
        raise KEKProtectionError("Master key must be a 32-byte key.")

    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=protected.salt,
        info=_KEK_PROTECTION_INFO,
    ).derive(master_key)

    aad = f"kek-version:{kek_version}".encode("utf-8")

    try:
        kek = AESGCM(wrapping_key).decrypt(protected.nonce, protected.encrypted_kek, aad)
    except InvalidTag:
        raise KEKProtectionError("KEK authentication failed – wrong master key or corrupted data.") from None
    except Exception as exc:
        raise KEKProtectionError("Failed to decrypt KEK.") from exc

    if len(kek) != AES_KEY_SIZE:
        raise KEKProtectionError("Decrypted KEK has invalid length.")
    return kek


# ---------------------------------------------------------------------------
# DEK wrapping / unwrapping
# ---------------------------------------------------------------------------

def generate_dek() -> bytes:
    """Generate a fresh 256-bit Data Encryption Key."""
    return AESGCM.generate_key(bit_length=256)


def wrap_dek(dek: bytes, kek: bytes, file_id: int) -> WrappedDEK:
    """Wrap (encrypt) a DEK using a KEK with file-bound AAD.

    The AAD binds the wrapped DEK to a specific file ID, preventing
    cross-file key-substitution attacks.
    """
    if not isinstance(dek, bytes) or len(dek) != AES_KEY_SIZE:
        raise DEKWrapError("DEK must be a 32-byte key.")
    if not isinstance(kek, bytes) or len(kek) != AES_KEY_SIZE:
        raise DEKWrapError("KEK must be a 32-byte key.")

    nonce = os.urandom(_NONCE_SIZE)
    aad = f"dek-file:{file_id}".encode("utf-8")

    try:
        wrapped = AESGCM(kek).encrypt(nonce, dek, aad)
    except Exception as exc:
        raise DEKWrapError("Failed to wrap DEK.") from exc

    return WrappedDEK(wrapped_dek=wrapped, nonce=nonce)


def unwrap_dek(wrapped: WrappedDEK, kek: bytes, file_id: int) -> bytes:
    """Unwrap (decrypt) a DEK using its KEK."""
    if not isinstance(kek, bytes) or len(kek) != AES_KEY_SIZE:
        raise DEKWrapError("KEK must be a 32-byte key.")

    aad = f"dek-file:{file_id}".encode("utf-8")

    try:
        dek = AESGCM(kek).decrypt(wrapped.nonce, wrapped.wrapped_dek, aad)
    except InvalidTag:
        raise DEKWrapError("DEK authentication failed – wrong KEK or corrupted data.") from None
    except Exception as exc:
        raise DEKWrapError("Failed to unwrap DEK.") from exc

    if len(dek) != AES_KEY_SIZE:
        raise DEKWrapError("Unwrapped DEK has invalid length.")
    return dek


def rewrap_dek(
    wrapped: WrappedDEK,
    old_kek: bytes,
    new_kek: bytes,
    file_id: int,
) -> WrappedDEK:
    """Re-wrap a DEK from an old KEK to a new KEK without exposing the file.

    This is the core of non-disruptive KEK rotation: the DEK (and therefore
    the file ciphertext) never changes – only the DEK's envelope is replaced.
    """
    dek = unwrap_dek(wrapped, old_kek, file_id)
    try:
        return wrap_dek(dek, new_kek, file_id)
    finally:
        # Best-effort: clear the plaintext DEK from the local variable.
        del dek


# ---------------------------------------------------------------------------
# Envelope encryption helpers (file-level)
# ---------------------------------------------------------------------------

def envelope_encrypt(
    plaintext: bytes,
    dek: bytes,
    file_id: int,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using a DEK.  Returns ``(nonce, ciphertext_with_tag)``.

    This wraps :func:`crypto.aes.encrypt_bytes` with file-bound AAD.
    """
    if not isinstance(dek, bytes) or len(dek) != AES_KEY_SIZE:
        raise DEKWrapError("DEK must be a 32-byte key.")

    combined_aad = f"envelope-file:{file_id}".encode("utf-8")
    if aad:
        combined_aad += b"|" + aad

    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, combined_aad)
    return nonce, ciphertext


def envelope_decrypt(
    nonce: bytes,
    ciphertext: bytes,
    dek: bytes,
    file_id: int,
    aad: bytes = b"",
) -> bytes:
    """Decrypt ciphertext using a DEK."""
    if not isinstance(dek, bytes) or len(dek) != AES_KEY_SIZE:
        raise DEKWrapError("DEK must be a 32-byte key.")

    combined_aad = f"envelope-file:{file_id}".encode("utf-8")
    if aad:
        combined_aad += b"|" + aad

    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, combined_aad)
    except InvalidTag:
        raise DEKWrapError("Envelope decryption failed – authentication error.") from None
