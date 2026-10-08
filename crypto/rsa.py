"""RSA key generation and interoperable PEM serialization."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class KeyFormatError(Exception):
    """Raised when serialized RSA key data is invalid or has the wrong key type."""


def generate_rsa_keypair(
    bits: int = 3072,
    public_exponent: int = 65537,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair; key sizes below 2048 bits are rejected."""
    if not isinstance(bits, int) or bits < 2048 or bits % 256:
        raise ValueError("RSA key size must be at least 2048 bits and a multiple of 256.")
    if public_exponent != 65537:
        raise ValueError("RSA public exponent must be 65537.")

    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=bits,
    )
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: RSAPrivateKey) -> bytes:
    """Serialize a private key to transient unencrypted PKCS#8 PEM bytes.

    The returned bytes must only be held in memory long enough to protect or
    load the key. Persist keys using ``crypto.key_storage.protect_private_key``.
    """
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("An RSA private key is required.")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem: bytes) -> RSAPrivateKey:
    """Load an unencrypted PKCS#8 PEM private key from trusted in-memory bytes."""
    if not isinstance(pem, bytes):
        raise TypeError("Serialized private key must be bytes.")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError):
        raise KeyFormatError("Invalid or encrypted RSA private-key PEM.") from None
    if not isinstance(key, RSAPrivateKey):
        raise KeyFormatError("Serialized key is not an RSA private key.")
    return key


def public_key_to_pem(public_key: RSAPublicKey) -> bytes:
    """Serialize an RSA public key as SubjectPublicKeyInfo PEM."""
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("An RSA public key is required.")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem: bytes) -> RSAPublicKey:
    """Load an RSA SubjectPublicKeyInfo PEM public key."""
    if not isinstance(pem, bytes):
        raise TypeError("Serialized public key must be bytes.")
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError):
        raise KeyFormatError("Invalid RSA public-key PEM.") from None
    if not isinstance(key, RSAPublicKey):
        raise KeyFormatError("Serialized key is not an RSA public key.")
    return key


def public_key_fingerprint(public_key: RSAPublicKey) -> str:
    """Return the SHA-256 fingerprint of a SubjectPublicKeyInfo DER key."""
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("An RSA public key is required.")
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()
