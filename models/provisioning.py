"""Provision user RSA keys and a CA-issued X.509 certificate atomically."""
from __future__ import annotations

from pathlib import Path

from flask import current_app

from crypto.ca import init_ca, issue_user_certificate
from crypto.certificates import load_certificate
from crypto.key_storage import protect_private_key
from crypto.rsa import generate_rsa_keypair, public_key_to_pem
from database.db import get_db


def provision_user_crypto(user_id: int, name: str, email: str, password: str) -> None:
    """Generate protected RSA-3072 key material and issue the user's certificate.

    The existing Phase 3 private-key protection contract is preserved: the private
    key is encrypted using the configured application secret and bound to user_id.
    No private key or password is written to the certificate database/file records.
    """
    del password  # Phase 3 protection deliberately uses the configured app secret.

    private_key, public_key = generate_rsa_keypair()
    app_secret = current_app.config["SECRET_KEY"]
    public_pem = public_key_to_pem(public_key)
    protected_private_key = protect_private_key(private_key, app_secret, user_id)

    # Test applications get an isolated disposable CA automatically; production
    # requires an explicit CIPHERLOCK_CA_PASSPHRASE and init_ca.py.
    if current_app.testing and not current_app.config.get("CIPHERLOCK_CA_PASSPHRASE"):
        current_app.config["CIPHERLOCK_CA_PASSPHRASE"] = "test-only-ca-passphrase-32-bytes!!"
    ca_key = Path(current_app.config["CA_KEYS_DIR"]) / "ca_key.pem"
    ca_cert = Path(current_app.config["CA_CERTIFICATES_DIR"]) / "ca_cert.pem"
    if current_app.testing and not ca_key.exists() and not ca_cert.exists():
        init_ca()

    # CA issuance is performed before the database update so a missing/broken CA
    # causes the existing registration transaction to roll back completely.
    certificate_pem, serial = issue_user_certificate(name, email, public_key)
    certificate = load_certificate(certificate_pem)

    db = get_db()
    cursor = db.execute(
        """
        UPDATE users
        SET public_key = ?, encrypted_private_key = ?, certificate = ?
        WHERE id = ?
        """,
        (public_pem, protected_private_key, certificate_pem, user_id),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("Could not persist user cryptographic keys and certificate.")

    db.execute(
        """
        INSERT INTO certificates
            (user_id, certificate, serial_number, issued_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        (
            user_id,
            certificate_pem,
            str(serial),
            certificate.not_valid_before_utc.isoformat(),
            certificate.not_valid_after_utc.isoformat(),
        ),
    )

    cert_dir = Path(current_app.config["USER_CERTIFICATES_DIR"])
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / f"{user_id}.pem"
    cert_path.write_bytes(certificate_pem)
    try:
        cert_path.chmod(0o644)
    except OSError:
        pass
