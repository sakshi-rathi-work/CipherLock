"""End-to-end tests for the Phase 6 hybrid secure package."""

from __future__ import annotations

import copy
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from app import create_app
from crypto.ca import init_ca, issue_user_certificate
from crypto.package import (
    TamperError,
    build_package,
    canonical_header,
    open_package,
    verify_package,
)
from crypto.rsa import UnwrapError, generate_rsa_keypair
from crypto.signatures import sha256_hex, sign_data
from database.db import get_db


@pytest.fixture(scope="module")
def package_context(tmp_path_factory):
    base = tmp_path_factory.mktemp("phase6")
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "phase-6-tests-only",
        "DATABASE_PATH": base / "db.sqlite",
        "STORAGE_DIR": base / "storage",
        "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
        "CERTIFICATES_DIR": base / "certificates",
        "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": base / "certificates" / "users",
        "KEYS_DIR": base / "keys",
        "CA_KEYS_DIR": base / "keys" / "ca",
        "USER_KEYS_DIR": base / "keys" / "users",
        "CIPHERLOCK_CA_PASSPHRASE": "phase-6-tests-ca-passphrase",
    })
    with app.app_context():
        ca_private_key, _ = init_ca()
        db = get_db()
        db.executemany(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [("Siddharth", "siddharth@example.test"), ("Vidhi", "vidhi@example.test")],
        )
        db.commit()
        alice_private_key, alice_public_key = generate_rsa_keypair()
        bob_private_key, bob_public_key = generate_rsa_keypair()
        alice_cert, alice_serial = issue_user_certificate(
            "Siddharth", "siddharth@example.test", alice_public_key
        )
        bob_cert, bob_serial = issue_user_certificate(
            "Vidhi", "vidhi@example.test", bob_public_key
        )
        alice_id, bob_id = 1, 2
        now = datetime.now(timezone.utc)
        db.executemany(
            """INSERT INTO certificates
               (user_id, certificate, serial_number, issued_at, expires_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            [
                (alice_id, alice_cert, str(alice_serial), now.isoformat(),
                 (now + timedelta(days=365)).isoformat()),
                (bob_id, bob_cert, str(bob_serial), now.isoformat(),
                 (now + timedelta(days=365)).isoformat()),
            ],
        )
        expired_private_key, expired_public_key = generate_rsa_keypair()
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Expired Sender"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "expired@example.test"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "CipherLock Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CipherLock"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            ]))
            .public_key(expired_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=3))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=2))
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
            .sign(ca_private_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )
        expired_serial = x509.load_pem_x509_certificate(expired_cert).serial_number
        db.execute(
            """INSERT INTO certificates
               (user_id, certificate, serial_number, issued_at, expires_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (alice_id, expired_cert, str(expired_serial), "expired", "expired"),
        )

        rogue_ca_key, rogue_ca_public = generate_rsa_keypair()
        rogue_cert_obj = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")]))
            .public_key(rogue_ca_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(rogue_ca_key, hashes.SHA256())
        )
        rogue_user_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Sender"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "siddharth@example.test"),
            ]))
            .issuer_name(rogue_cert_obj.subject)
            .public_key(alice_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(rogue_ca_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )
        rogue_serial = x509.load_pem_x509_certificate(rogue_user_cert).serial_number
        db.execute(
            """INSERT INTO certificates
               (user_id, certificate, serial_number, issued_at, expires_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (alice_id, rogue_user_cert, str(rogue_serial), "now", "later"),
        )
        db.commit()

        yield {
            "app": app,
            "alice_private": alice_private_key,
            "alice_public": alice_public_key,
            "alice_cert": alice_cert,
            "alice_serial": alice_serial,
            "bob_private": bob_private_key,
            "bob_public": bob_public_key,
            "bob_cert": bob_cert,
            "alice_id": alice_id,
            "bob_id": bob_id,
            "expired_private": expired_private_key,
            "expired_cert": expired_cert,
            "rogue_cert": rogue_user_cert,
        }


@pytest.fixture
def valid_package(package_context):
    ctx = package_context
    plaintext = os.urandom(5 * 1024 * 1024)
    with ctx["app"].app_context():
        package = build_package(
            plaintext,
            "sample.bin",
            ctx["alice_id"],
            ctx["bob_id"],
            ctx["alice_private"],
            ctx["alice_cert"],
            ctx["bob_public"],
        )
    return package, plaintext


def test_happy_path_round_trip_with_random_five_megabyte_file(package_context, valid_package):
    ctx = package_context
    package, expected_plaintext = valid_package
    with ctx["app"].app_context():
        report = verify_package(package, "siddharth@example.test")
    assert (report.certificate, report.signature, report.integrity, report.overall) == (
        "VALID", "VALID", "PASSED", "TRUSTED"
    )
    with ctx["app"].app_context():
        original = open_package(package, ctx["bob_private"], "siddharth@example.test")
    assert len(original) == 5 * 1024 * 1024
    assert sha256_hex(original) == sha256_hex(expected_plaintext)


def test_ciphertext_byte_flip_is_detected_before_open(package_context, valid_package):
    package, _ = valid_package
    altered = copy.deepcopy(package)
    value = bytearray(altered["ciphertext_with_tag"])
    value[0] ^= 1
    altered["ciphertext_with_tag"] = bytes(value)
    with package_context["app"].app_context():
        report = verify_package(altered)
        assert (report.certificate, report.signature, report.integrity, report.overall) == (
            "VALID", "INVALID", "FAILED", "POSSIBLE TAMPERING"
        )
        with pytest.raises(TamperError):
            open_package(altered, package_context["bob_private"])


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("original_filename", "renamed.bin"), ("receiver_id", 999)],
)
def test_signed_metadata_changes_are_detected(valid_package, package_context, field, replacement):
    package, _ = valid_package
    altered = copy.deepcopy(package)
    altered[field] = replacement
    with package_context["app"].app_context():
        report = verify_package(altered)
    assert report.signature == "INVALID"
    assert report.integrity == "FAILED"
    assert report.overall == "POSSIBLE TAMPERING"


def test_signature_from_another_user_is_rejected(valid_package, package_context):
    package, _ = valid_package
    altered = copy.deepcopy(package)
    header = canonical_header(
        altered["version"], altered["sender_id"], altered["receiver_id"],
        altered["original_filename"], altered["nonce"], altered["wrapped_key"],
        sha256_hex(altered["ciphertext_with_tag"]), altered["sender_cert_serial"],
    )
    other_private_key, _ = generate_rsa_keypair()
    altered["signature"] = sign_data(other_private_key, header)
    with package_context["app"].app_context():
        report = verify_package(altered)
    assert report.signature == "INVALID"
    assert report.integrity == "FAILED"


def test_rogue_ca_certificate_is_untrusted(valid_package, package_context):
    package, _ = valid_package
    altered = copy.deepcopy(package)
    altered["sender_cert_pem"] = package_context["rogue_cert"]
    with package_context["app"].app_context():
        report = verify_package(altered)
    assert report.certificate == "INVALID"
    assert report.overall == "UNTRUSTED SENDER"


def test_expired_sender_certificate_is_untrusted(package_context):
    ctx = package_context
    with ctx["app"].app_context():
        package = build_package(
            b"expired cert test", "expired.txt", ctx["alice_id"], ctx["bob_id"],
            ctx["expired_private"], ctx["expired_cert"], ctx["bob_public"],
        )
        report = verify_package(package, "expired@example.test")
    assert report.certificate == "INVALID"
    assert report.signature == "VALID"
    assert report.overall == "UNTRUSTED SENDER"


def test_revoked_sender_certificate_is_untrusted(valid_package, package_context):
    ctx = package_context
    package, _ = valid_package
    with ctx["app"].app_context():
        db = get_db()
        db.execute(
            "UPDATE certificates SET status = 'revoked' WHERE serial_number = ?",
            (str(ctx["alice_serial"]),),
        )
        db.commit()
        try:
            report = verify_package(package)
            assert report.certificate == "INVALID"
            assert report.overall == "UNTRUSTED SENDER"
        finally:
            db.execute(
                "UPDATE certificates SET status = 'active' WHERE serial_number = ?",
                (str(ctx["alice_serial"]),),
            )
            db.commit()


def test_wrong_recipient_private_key_cannot_open_package(valid_package, package_context):
    package, _ = valid_package
    wrong_private_key, _ = generate_rsa_keypair()
    with package_context["app"].app_context():
        with pytest.raises(UnwrapError):
            open_package(package, wrong_private_key)


def test_ciphertext_and_public_metadata_do_not_reveal_content(valid_package, package_context):
    package, _ = valid_package
    attacker_view = {
        key: copy.deepcopy(package[key])
        for key in (
            "version", "sender_id", "receiver_id", "original_filename", "nonce",
            "wrapped_key", "ciphertext_with_tag", "ciphertext_sha256_hex",
            "signature", "sender_cert_pem", "sender_cert_serial",
        )
    }
    assert "session_key" not in attacker_view
    with package_context["app"].app_context():
        assert verify_package(attacker_view).overall == "TRUSTED"
        with pytest.raises(TypeError, match="receiver private key"):
            open_package(attacker_view, None)
