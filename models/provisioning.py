"""Phase 2 placeholder for cryptographic user provisioning.

Phase 3 will generate the RSA-3072 key pair here and store
public_key + encrypted_private_key (PKCS#8, passphrase = password); Phase 4 adds the
X.509 certificate. Runs inside the registration transaction (rolls back on error).
MUST NOT store, log, or return the password.
"""
from __future__ import annotations


def provision_user_crypto(user_id: int, name: str, email: str, password: str) -> None:
    """Phase 2 placeholder. Phase 3 will generate the RSA-3072 key pair here and store
    public_key + encrypted_private_key (PKCS#8, passphrase = password); Phase 4 adds the
    X.509 certificate. Runs inside the registration transaction (rolls back on error).
    MUST NOT store, log, or return the password."""
    return None
