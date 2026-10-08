"""X.509 certificate loading and fail-closed CipherLock certificate validation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app

from crypto.ca import load_ca
from database.db import get_db


@dataclass(frozen=True)
class CertReport:
    ca_signature_ok: bool
    validity_ok: bool
    not_revoked: bool
    subject_ok: bool
    key_usage_ok: bool
    valid: bool
    reason: str


def load_certificate(pem: bytes) -> x509.Certificate:
    if not isinstance(pem, bytes):
        raise TypeError("Certificate PEM must be bytes.")
    try:
        return x509.load_pem_x509_certificate(pem)
    except (TypeError, ValueError):
        raise ValueError("Invalid X.509 certificate PEM.") from None


def _utc_bounds(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    before = getattr(certificate, "not_valid_before_utc", None)
    after = getattr(certificate, "not_valid_after_utc", None)
    if before is None:
        before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if after is None:
        after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def verify_certificate(
    cert_pem: bytes,
    expected_email: str | None = None,
) -> CertReport:
    """Validate CA trust, time validity, database revocation and key usage."""
    try:
        certificate = load_certificate(cert_pem)
    except (TypeError, ValueError) as exc:
        return CertReport(False, False, False, False, False, False, str(exc))

    try:
        _, ca_certificate = load_ca()
    except Exception as exc:
        return CertReport(False, False, False, False, False, False, f"CA unavailable: {exc}")

    ca_signature_ok = False
    try:
        ca_public_key = ca_certificate.public_key()
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            raise ValueError("Root CA key is not RSA.")
        if certificate.issuer != ca_certificate.subject:
            raise ValueError("Certificate issuer does not match the Root CA.")
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        ca_signature_ok = True
    except (InvalidSignature, ValueError, TypeError):
        ca_signature_ok = False

    now = datetime.now(timezone.utc)
    before, after = _utc_bounds(certificate)
    validity_ok = before <= now <= after

    db = get_db()
    row = db.execute(
        "SELECT status FROM certificates WHERE serial_number = ? LIMIT 1",
        (str(certificate.serial_number),),
    ).fetchone()
    not_revoked = row is not None and row["status"] != "revoked"

    subject_email = None
    try:
        subject_email = certificate.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value
    except IndexError:
        pass
    subject_ok = expected_email is None or (
        subject_email is not None and subject_email.lower() == expected_email.strip().lower()
    )

    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        key_usage_ok = usage.digital_signature and usage.key_encipherment
    except x509.ExtensionNotFound:
        key_usage_ok = False

    checks = [
        (ca_signature_ok, "certificate is not signed by the trusted Root CA"),
        (validity_ok, "certificate is outside its validity period"),
        (not_revoked, "certificate is revoked or not registered in CipherLock"),
        (subject_ok, "certificate identity does not match the expected email"),
        (key_usage_ok, "certificate KeyUsage is missing digitalSignature/keyEncipherment"),
    ]
    for passed, reason in checks:
        if not passed:
            return CertReport(
                ca_signature_ok,
                validity_ok,
                not_revoked,
                subject_ok,
                key_usage_ok,
                False,
                reason,
            )

    return CertReport(
        ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, True, "Certificate is valid."
    )
