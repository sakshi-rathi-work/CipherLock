"""Provision protected RSA keys for newly registered CipherLock users."""
from __future__ import annotations

from flask import current_app

from crypto.key_storage import protect_private_key
from crypto.rsa import generate_rsa_keypair, public_key_to_pem

from database.db import get_db


def provision_user_crypto(user_id: int, name: str, email: str, password: str) -> None:
    """Generate and store RSA-3072 key material inside registration's transaction.

    The password argument remains for compatibility with the existing hook but is
    deliberately not used to protect or persist private-key material. Protection
    derives from the application's configured SECRET_KEY and is bound to user_id.
    """
    del name, email, password
    private_key, public_key = generate_rsa_keypair()
    app_secret = current_app.config["SECRET_KEY"]
    public_pem = public_key_to_pem(public_key)
    protected_private_key = protect_private_key(private_key, app_secret, user_id)

    db = get_db()
    cursor = db.execute(
        """
        UPDATE users
        SET public_key = ?, encrypted_private_key = ?
        WHERE id = ?
        """,
        (public_pem, protected_private_key, user_id),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("Could not persist user cryptographic keys.")
