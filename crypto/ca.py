"""CipherLock mini Certificate Authority (Root CA) implementation."""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID
from flask import current_app

from database.db import get_db

CA_COMMON_NAME = "CipherLock Root CA"
CA_ORGANIZATION = "CipherLock"
CA_COUNTRY = "IN"
CA_VALIDITY_DAYS = 3650
USER_VALIDITY_DAYS = 365


class CAConfigurationError(RuntimeError):
    """Raised when the CA cannot be safely initialized or loaded."""


def _paths() -> tuple[Path, Path]:
    return (
        Path(current_app.config["CA_KEYS_DIR"]) / "ca_key.pem",
        Path(current_app.config["CA_CERTIFICATES_DIR"]) / "ca_cert.pem",
    )


def _passphrase() -> bytes:
    value = str(current_app.config.get("CIPHERLOCK_CA_PASSPHRASE", ""))
    if not value:
        raise CAConfigurationError(
            "CIPHERLOCK_CA_PASSPHRASE is required to initialize or load the Root CA."
        )
    if len(value.encode("utf-8")) < 16:
        raise CAConfigurationError("CIPHERLOCK_CA_PASSPHRASE must contain at least 16 bytes.")
    return value.encode("utf-8")


def _secure_mode(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        # Windows uses ACLs; chmod is best effort there.
        pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def init_ca() -> tuple[RSAPrivateKey, x509.Certificate]:
    """Create the encrypted RSA-4096 self-signed Root CA exactly once."""
    passphrase = _passphrase()
    key_path, cert_path = _paths()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists() or cert_path.exists():
        if not (key_path.exists() and cert_path.exists()):
            raise CAConfigurationError("CA files are incomplete; refusing partial initialization.")
        return load_ca()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
    ])
    now = _utc_now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    encrypted_key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    # Refuse to leave a readable CA key behind if writing fails midway.
    key_path.write_bytes(encrypted_key)
    _secure_mode(key_path)
    cert_path.write_bytes(cert_pem)
    return private_key, certificate


def load_ca() -> tuple[RSAPrivateKey, x509.Certificate]:
    """Load and authenticate the encrypted Root CA key and certificate."""
    passphrase = _passphrase()
    key_path, cert_path = _paths()
    if not key_path.exists() or not cert_path.exists():
        raise FileNotFoundError("Root CA is not initialized. Run scripts/init_ca.py first.")

    try:
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=passphrase
        )
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (TypeError, ValueError, OSError) as exc:
        raise CAConfigurationError("Root CA key or certificate could not be loaded.") from exc

    if not isinstance(private_key, RSAPrivateKey) or private_key.key_size != 4096:
        raise CAConfigurationError("Root CA private key must be RSA-4096.")
    if not isinstance(certificate.public_key(), RSAPublicKey):
        raise CAConfigurationError("Root CA certificate does not contain an RSA public key.")
    if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
        raise CAConfigurationError("Root CA private key does not match the CA certificate.")
    if certificate.subject != certificate.issuer:
        raise CAConfigurationError("Root CA certificate must be self-issued.")
    try:
        private_key.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except (InvalidSignature, ValueError, TypeError):
        raise CAConfigurationError("Root CA certificate self-signature is invalid.") from None
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not constraints.ca or constraints.path_length != 0 or not (usage.key_cert_sign and usage.crl_sign):
            raise CAConfigurationError("Root CA certificate has invalid CA constraints or KeyUsage.")
    except x509.ExtensionNotFound:
        raise CAConfigurationError("Root CA certificate is missing required CA extensions.") from None
    return private_key, certificate


def _unique_serial() -> int:
    db = get_db()
    while True:
        serial = secrets.randbits(159) or 1
        row = db.execute(
            "SELECT 1 FROM certificates WHERE serial_number = ? LIMIT 1", (str(serial),)
        ).fetchone()
        if row is None:
            return serial


def issue_user_certificate(
    name: str,
    email: str,
    public_key: RSAPublicKey,
) -> tuple[bytes, int]:
    """Issue a one-year X.509 v3 end-entity certificate for a user key."""
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("An RSA public key is required.")
    if public_key.key_size != 3072:
        raise ValueError("CipherLock user certificates require RSA-3072 public keys.")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
        raise ValueError("Certificate subject name is invalid.")
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
        raise ValueError("Certificate email is invalid.")

    ca_private_key, ca_certificate = load_ca()
    now = _utc_now()
    serial = _unique_serial()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name.strip()),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email.strip().lower()),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=USER_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email.strip().lower())]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), serial


def revoke_certificate(serial: int | str) -> bool:
    """Revoke a certificate by serial number; returns whether a row changed."""
    try:
        normalized = str(int(serial))
    except (TypeError, ValueError):
        raise ValueError("Certificate serial must be an integer.") from None
    db = get_db()
    cursor = db.execute(
        "UPDATE certificates SET status = 'revoked' WHERE serial_number = ? AND status = 'active'",
        (normalized,),
    )
    db.commit()
    return cursor.rowcount == 1
