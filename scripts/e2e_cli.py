"""Run a temporary end-to-end CipherLock package and tamper demonstration."""

from __future__ import annotations

import copy
import hashlib
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from crypto.ca import init_ca, issue_user_certificate
from crypto.package import (
    build_package,
    canonical_header,
    format_security_box,
    open_package,
    verify_package,
)
from crypto.rsa import UnwrapError, generate_rsa_keypair
from crypto.signatures import sha256_hex, sign_data
from database.db import get_db


def _add_certificate_row(db, user_id: int, cert_pem: bytes) -> None:
    cert = x509.load_pem_x509_certificate(cert_pem)
    before = cert.not_valid_before_utc
    after = cert.not_valid_after_utc
    db.execute(
        """INSERT INTO certificates
           (user_id, certificate, serial_number, issued_at, expires_at, status)
           VALUES (?, ?, ?, ?, ?, 'active')""",
        (user_id, cert_pem, str(cert.serial_number), before.isoformat(), after.isoformat()),
    )


def _make_expired_certificate(ca_key, ca_cert, user_public_key) -> bytes:
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Expired Sender"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "expired@example.test"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now - timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("expired@example.test")]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def _make_rogue_certificate(user_public_key) -> bytes:
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Demo CA")])
    now = datetime.now(timezone.utc)
    rogue_ca = (
        x509.CertificateBuilder()
        .subject_name(rogue_name)
        .issuer_name(rogue_name)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(rogue_key, hashes.SHA256())
    )
    user_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Siddharth"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "siddharth@example.test"),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(user_name)
        .issuer_name(rogue_ca.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(rogue_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def main() -> int:
    results: list[tuple[str, str, str]] = []
    with tempfile.TemporaryDirectory(prefix="cipherlock-phase6-") as temp:
        base = Path(temp)
        app = create_app({
            "TESTING": True,
            "SECRET_KEY": "temporary-phase-6-cli-demo-only",
            "DATABASE_PATH": base / "database" / "cipherlock.db",
            "STORAGE_DIR": base / "storage",
            "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
            "CERTIFICATES_DIR": base / "certificates",
            "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
            "USER_CERTIFICATES_DIR": base / "certificates" / "users",
            "KEYS_DIR": base / "keys",
            "CA_KEYS_DIR": base / "keys" / "ca",
            "USER_KEYS_DIR": base / "keys" / "users",
            "CIPHERLOCK_CA_PASSPHRASE": "temporary-cli-ca-passphrase-2026",
        })

        with app.app_context():
            ca_key, ca_cert = init_ca()
            db = get_db()
            db.executemany(
                "INSERT INTO users (name, email) VALUES (?, ?)",
                [("Siddharth", "siddharth@example.test"), ("Vidhi", "vidhi@example.test")],
            )
            db.commit()

            sender_private, sender_public = generate_rsa_keypair()
            receiver_private, receiver_public = generate_rsa_keypair()
            sender_cert, sender_serial = issue_user_certificate(
                "Siddharth", "siddharth@example.test", sender_public
            )
            receiver_cert, _ = issue_user_certificate(
                "Vidhi", "vidhi@example.test", receiver_public
            )
            _add_certificate_row(db, 1, sender_cert)
            _add_certificate_row(db, 2, receiver_cert)

            expired_private, expired_public = generate_rsa_keypair()
            expired_cert = _make_expired_certificate(ca_key, ca_cert, expired_public)
            _add_certificate_row(db, 1, expired_cert)
            db.commit()

            plaintext = b"CipherLock Phase 6 end-to-end proof\n" + os.urandom(128 * 1024)
            package = build_package(
                plaintext, "proof.bin", 1, 2, sender_private, sender_cert, receiver_public
            )
            report = verify_package(package, "siddharth@example.test")
            recovered = open_package(package, receiver_private, "siddharth@example.test")
            assert report.overall == "TRUSTED"
            assert hashlib.sha256(recovered).digest() == hashlib.sha256(plaintext).digest()
            print(format_security_box(report))
            print(f"Round-trip SHA-256: {hashlib.sha256(recovered).hexdigest()} (MATCH)\n")

            def record(label: str, expected: str, actual: str) -> None:
                results.append((label, expected, actual))

            # 1. Ciphertext byte flip.
            altered = copy.deepcopy(package)
            ciphertext = bytearray(altered["ciphertext_with_tag"])
            ciphertext[len(ciphertext) // 2] ^= 1
            altered["ciphertext_with_tag"] = bytes(ciphertext)
            status = verify_package(altered).overall
            record("1. Ciphertext byte flip", "POSSIBLE TAMPERING", status)

            # 2. Filename substitution.
            altered = copy.deepcopy(package)
            altered["original_filename"] = "substituted.bin"
            record(
                "2. Filename changed", "POSSIBLE TAMPERING",
                verify_package(altered).overall,
            )

            # 3. Recipient substitution.
            altered = copy.deepcopy(package)
            altered["receiver_id"] = 999
            record(
                "3. Receiver ID changed", "POSSIBLE TAMPERING",
                verify_package(altered).overall,
            )

            # 4. Signature replaced by one made by another principal.
            altered = copy.deepcopy(package)
            signed_header = canonical_header(
                altered["version"], altered["sender_id"], altered["receiver_id"],
                altered["original_filename"], altered["nonce"], altered["wrapped_key"],
                sha256_hex(altered["ciphertext_with_tag"]), altered["sender_cert_serial"],
            )
            other_private, _ = generate_rsa_keypair()
            altered["signature"] = sign_data(other_private, signed_header)
            record(
                "4. Signature from another user", "POSSIBLE TAMPERING",
                verify_package(altered).overall,
            )

            # 5. Certificate replaced with one issued by a rogue CA.
            altered = copy.deepcopy(package)
            altered["sender_cert_pem"] = _make_rogue_certificate(sender_public)
            record(
                "5. Rogue CA certificate", "UNTRUSTED SENDER",
                verify_package(altered).overall,
            )

            # 6. Package signed with a CA-signed but expired identity certificate.
            expired_package = build_package(
                b"expired test", "expired.txt", 1, 2, expired_private,
                expired_cert, receiver_public,
            )
            record(
                "6. Expired sender certificate", "UNTRUSTED SENDER",
                verify_package(expired_package, "expired@example.test").overall,
            )

            # 7. Database revocation status is checked during certificate validation.
            db.execute(
                "UPDATE certificates SET status = 'revoked' WHERE serial_number = ?",
                (str(sender_serial),),
            )
            db.commit()
            revoked_report = verify_package(package).overall
            db.execute(
                "UPDATE certificates SET status = 'active' WHERE serial_number = ?",
                (str(sender_serial),),
            )
            db.commit()
            record("7. Revoked sender certificate", "UNTRUSTED SENDER", revoked_report)

            # 8. A different recipient key cannot unwrap the AES key.
            wrong_private, _ = generate_rsa_keypair()
            try:
                open_package(package, wrong_private)
                wrong_recipient_result = "OPENED (UNEXPECTED)"
            except UnwrapError:
                wrong_recipient_result = "UNWRAP REJECTED"
            record("8. Wrong recipient key", "UNWRAP REJECTED", wrong_recipient_result)

            # 9. Public package material is not a substitute for the private key.
            try:
                open_package(package, None)  # type: ignore[arg-type]
                attacker_result = "OPENED (UNEXPECTED)"
            except TypeError:
                attacker_result = "NO PRIVATE KEY"
            record("9. Attacker without private key", "NO PRIVATE KEY", attacker_result)

    print("Attack-case results (expected vs actual):")
    print(f"{'Case':<38} {'Expected':<24} Actual")
    print("-" * 90)
    for label, expected, actual in results:
        outcome = "PASS" if expected == actual else "FAIL"
        print(f"{label:<38} {expected:<24} {actual} [{outcome}]")
    failed = [row for row in results if row[1] != row[2]]
    print(f"\nResult: {'FAIL' if failed else 'PASS'} — {len(results) - len(failed)}/{len(results)} attack cases matched.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
