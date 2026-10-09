"""Hybrid encrypted package creation, verification, and opening."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto.aes import decrypt_bytes, encrypt_bytes, generate_session_key
from crypto.certificates import load_certificate, verify_certificate
from crypto.rsa import UnwrapError, unwrap_session_key, wrap_session_key
from crypto.signatures import sha256_hex, sign_data, verify_signature

PACKAGE_VERSION = 1
SIGNATURE_FAILURE_MESSAGE = (
    "Signature verification failed. File may have been modified or sender "
    "authenticity could not be established."
)


@dataclass(frozen=True)
class SecurityReport:
    certificate: str
    signature: str
    integrity: str
    overall: str
    messages: list[str]


class TamperError(Exception):
    """Raised when a package is not trusted and must not be decrypted."""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Encoded package fields must be strings.")
    return base64.b64decode(value.encode("ascii"), validate=True)


def _certificate_serial(certificate_pem: bytes) -> int:
    certificate = load_certificate(certificate_pem)
    return certificate.serial_number


def canonical_header(
    version: int,
    sender_id: int,
    receiver_id: int,
    original_filename: str,
    nonce: bytes,
    wrapped_key: bytes,
    ciphertext_sha256_hex: str,
    sender_cert_serial: int,
) -> bytes:
    """Return the canonical D6 JSON signed by the sender.

    Binary nonce and wrapped key values are represented as standard Base64
    text; JSON key ordering and separators are fixed to avoid ambiguity.
    """
    header = {
        "version": version,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "original_filename": original_filename,
        "nonce_b64": _b64(nonce),
        "wrapped_key_b64": _b64(wrapped_key),
        "ciphertext_sha256_hex": ciphertext_sha256_hex,
        "sender_cert_serial": sender_cert_serial,
    }
    return json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _aad_header(
    version: int,
    sender_id: int,
    receiver_id: int,
    original_filename: str,
    sender_cert_serial: int,
) -> bytes:
    """Bind stable metadata with GCM before ciphertext/hash/key-wrap exist."""
    aad = {
        "version": version,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "original_filename": original_filename,
        "sender_cert_serial": sender_cert_serial,
    }
    return json.dumps(
        aad,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def build_package(
    plaintext: bytes,
    original_filename: str,
    sender_id: int,
    receiver_id: int,
    sender_private_key: RSAPrivateKey,
    sender_cert_pem: bytes,
    receiver_public_key: RSAPublicKey,
) -> dict[str, Any]:
    """Encrypt bytes for a recipient and sign the complete canonical header."""
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")
    if not isinstance(original_filename, str) or not original_filename:
        raise ValueError("Original filename must be a non-empty string.")
    if not isinstance(sender_private_key, RSAPrivateKey):
        raise TypeError("An RSA sender private key is required.")
    if not isinstance(receiver_public_key, RSAPublicKey):
        raise TypeError("An RSA receiver public key is required.")
    if not isinstance(sender_cert_pem, bytes):
        raise TypeError("Sender certificate must be PEM bytes.")
    if not isinstance(sender_id, int) or not isinstance(receiver_id, int):
        raise TypeError("Sender and receiver IDs must be integers.")

    serial = _certificate_serial(sender_cert_pem)
    aad = _aad_header(PACKAGE_VERSION, sender_id, receiver_id, original_filename, serial)

    session_key = generate_session_key()
    nonce, ciphertext_with_tag = encrypt_bytes(session_key, plaintext, aad)
    ciphertext_hash = sha256_hex(ciphertext_with_tag)
    wrapped_key = wrap_session_key(receiver_public_key, session_key)
    header_bytes = canonical_header(
        PACKAGE_VERSION,
        sender_id,
        receiver_id,
        original_filename,
        nonce,
        wrapped_key,
        ciphertext_hash,
        serial,
    )
    signature = sign_data(sender_private_key, header_bytes)
    del session_key

    return {
        "version": PACKAGE_VERSION,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "original_filename": original_filename,
        "nonce": nonce,
        "wrapped_key": wrapped_key,
        "ciphertext_with_tag": ciphertext_with_tag,
        "ciphertext_sha256_hex": ciphertext_hash,
        "signature": signature,
        "sender_cert_pem": sender_cert_pem,
        "sender_cert_serial": serial,
    }


def _package_value(package: dict[str, Any], name: str) -> Any:
    if not isinstance(package, dict) or name not in package:
        raise ValueError(f"Package is missing required field: {name}.")
    return package[name]


def _report(
    certificate: str,
    signature: str,
    integrity: str,
    messages: list[str],
) -> SecurityReport:
    if certificate != "VALID":
        overall = "UNTRUSTED SENDER"
    elif signature != "VALID" or integrity != "PASSED":
        overall = "POSSIBLE TAMPERING"
    else:
        overall = "TRUSTED"
    return SecurityReport(certificate, signature, integrity, overall, messages)


def verify_package(
    package: dict[str, Any],
    expected_sender_email: str | None = None,
) -> SecurityReport:
    """Verify sender trust and package integrity without decrypting content."""
    messages: list[str] = []
    try:
        cert_pem = _package_value(package, "sender_cert_pem")
        cert_report = verify_certificate(cert_pem, expected_sender_email)
        cert = load_certificate(cert_pem)
        serial_matches = cert.serial_number == _package_value(package, "sender_cert_serial")
        certificate_status = "VALID" if cert_report.valid and serial_matches else "INVALID"
        if not cert_report.valid:
            messages.append(cert_report.reason)
        if not serial_matches:
            messages.append("Package certificate serial does not match the sender certificate.")
        actual_hash = sha256_hex(_package_value(package, "ciphertext_with_tag"))
        recorded_hash = _package_value(package, "ciphertext_sha256_hex")
        hash_matches = (
            isinstance(recorded_hash, str)
            and len(recorded_hash) == 64
            and actual_hash == recorded_hash
        )
        if not hash_matches:
            messages.append("Ciphertext SHA-256 does not match the signed package header.")

        header_bytes = canonical_header(
            _package_value(package, "version"),
            _package_value(package, "sender_id"),
            _package_value(package, "receiver_id"),
            _package_value(package, "original_filename"),
            _package_value(package, "nonce"),
            _package_value(package, "wrapped_key"),
            actual_hash,
            _package_value(package, "sender_cert_serial"),
        )
        public_key = cert.public_key()
        signature_valid = isinstance(public_key, RSAPublicKey) and verify_signature(
            public_key,
            header_bytes,
            _package_value(package, "signature"),
        )
        signature_status = "VALID" if signature_valid else "INVALID"
        if not signature_valid:
            messages.append(SIGNATURE_FAILURE_MESSAGE)
        integrity_status = "PASSED" if hash_matches and signature_valid else "FAILED"
        return _report(certificate_status, signature_status, integrity_status, messages)
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        messages.append(f"Package verification could not be completed: {exc}")
        return _report("INVALID", "INVALID", "FAILED", messages)


def open_package(
    package: dict[str, Any],
    receiver_private_key: RSAPrivateKey,
    expected_sender_email: str | None = None,
) -> bytes:
    """Verify before unwrapping, then authenticate and decrypt in memory."""
    report = verify_package(package, expected_sender_email)
    if report.overall != "TRUSTED":
        raise TamperError(SIGNATURE_FAILURE_MESSAGE)
    if not isinstance(receiver_private_key, RSAPrivateKey):
        raise TypeError("An RSA receiver private key is required.")

    serial = _package_value(package, "sender_cert_serial")
    aad = _aad_header(
        _package_value(package, "version"),
        _package_value(package, "sender_id"),
        _package_value(package, "receiver_id"),
        _package_value(package, "original_filename"),
        serial,
    )
    session_key = unwrap_session_key(receiver_private_key, _package_value(package, "wrapped_key"))
    try:
        return decrypt_bytes(
            session_key,
            _package_value(package, "nonce"),
            _package_value(package, "ciphertext_with_tag"),
            aad,
        )
    finally:
        del session_key


def format_security_box(report: SecurityReport) -> str:
    """Format a verification result as the required CLI status box."""
    return "\n".join(
        [
            "--------------------------------",
            "CIPHERLOCK SECURITY CHECK",
            "--------------------------------",
            f"Certificate: {report.certificate}",
            f"Signature: {report.signature}",
            f"Integrity: {report.integrity}",
            f"Status: {report.overall}",
            "--------------------------------",
        ]
    )
