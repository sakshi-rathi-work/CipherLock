"""RSA-PSS digital signature and SHA-256 hashing utilities."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

PSS_SALT_LENGTH: int = 32


def sign_data(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """Sign data using RSA-PSS with SHA-256 digest and 32-byte salt length.

    Args:
        private_key: The signer's RSA private key.
        data: The payload bytes to sign.

    Returns:
        The RSA-PSS signature bytes.
    """
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("An RSA private key is required for signing.")
    if not isinstance(data, bytes):
        raise TypeError("Data to sign must be bytes.")

    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=PSS_SALT_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS digital signature over data using SHA-256 digest and 32-byte salt.

    Args:
        public_key: The signer's RSA public key.
        data: The payload bytes that were signed.
        signature: The RSA-PSS signature bytes to verify.

    Returns:
        True if the signature is valid for the given data and public key; False otherwise.
    """
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("An RSA public key is required for verification.")
    if not isinstance(data, bytes):
        raise TypeError("Data to verify must be bytes.")
    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes.")

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def sha256_hex(data: bytes) -> str:
    """Compute and return the SHA-256 hexadecimal digest of input bytes.

    Args:
        data: Input bytes to hash.

    Returns:
        Lowercase hexadecimal SHA-256 hash string (64 characters).
    """
    if not isinstance(data, bytes):
        raise TypeError("Input data must be bytes.")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()
