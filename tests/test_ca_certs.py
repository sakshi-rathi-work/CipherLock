"""Phase 4 mini-CA, X.509 issuance, validation and revocation tests."""
from __future__ import annotations

import sqlite3

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import create_app
from crypto.ca import init_ca, issue_user_certificate, revoke_certificate
from crypto.certificates import verify_certificate
from crypto.rsa import generate_rsa_keypair


@pytest.fixture
def ca_app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "phase-four-app-secret-with-32-bytes!!",
        "CIPHERLOCK_CA_PASSPHRASE": "phase-four-ca-passphrase-32-bytes!!",
        "DATABASE_PATH": tmp_path / "phase4.db",
        "STORAGE_DIR": tmp_path / "storage",
        "ENCRYPTED_STORAGE_DIR": tmp_path / "storage" / "encrypted",
        "CERTIFICATES_DIR": tmp_path / "certificates",
        "CA_CERTIFICATES_DIR": tmp_path / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": tmp_path / "certificates" / "users",
        "KEYS_DIR": tmp_path / "keys",
        "CA_KEYS_DIR": tmp_path / "keys" / "ca",
        "USER_KEYS_DIR": tmp_path / "keys" / "users",
    })
    return app


def test_init_ca_creates_encrypted_rsa4096_root(ca_app):
    with ca_app.app_context():
        private_key, cert = init_ca()
        key_path = ca_app.config["CA_KEYS_DIR"] / "ca_key.pem"
        cert_path = ca_app.config["CA_CERTIFICATES_DIR"] / "ca_cert.pem"
        assert private_key.key_size == 4096
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "CipherLock Root CA"
        assert cert.issuer == cert.subject
        assert cert_path.exists() and key_path.exists()
        encrypted = key_path.read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in encrypted
        assert b"PRIVATE KEY" in encrypted
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.key_cert_sign and usage.crl_sign


def test_user_certificate_is_valid_and_has_required_extensions(ca_app):
    with ca_app.app_context():
        init_ca()
        _, public_key = generate_rsa_keypair()
        pem, serial = issue_user_certificate("Alice Example", "alice@example.com", public_key)
        db = sqlite3.connect(ca_app.config["DATABASE_PATH"])
        db.execute(
            "INSERT INTO users (name,email,password_hash,is_admin,is_active) VALUES (?,?,?,?,?)",
            ("Alice Example", "alice@example.com", "test", 0, 1),
        )
        user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        cert = x509.load_pem_x509_certificate(pem)
        db.execute(
            "INSERT INTO certificates (user_id,certificate,serial_number,issued_at,expires_at,status) VALUES (?,?,?,?,?,?)",
            (user_id, pem, str(serial), cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat(), "active"),
        )
        db.commit(); db.close()
        report = verify_certificate(pem, expected_email="alice@example.com")
        assert report.valid
        assert all([report.ca_signature_ok, report.validity_ok, report.not_revoked, report.subject_ok, report.key_usage_ok])
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Alice Example"
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert "alice@example.com" in san.get_values_for_type(x509.RFC822Name)


def test_wrong_email_is_rejected(ca_app):
    with ca_app.app_context():
        init_ca(); _, public_key = generate_rsa_keypair()
        pem, serial = issue_user_certificate("Alice Example", "alice@example.com", public_key)
        db = sqlite3.connect(ca_app.config["DATABASE_PATH"])
        db.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)", ("Alice Example", "alice@example.com", "x"))
        uid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        cert = x509.load_pem_x509_certificate(pem)
        db.execute("INSERT INTO certificates (user_id,certificate,serial_number,issued_at,expires_at,status) VALUES (?,?,?,?,?,?)", (uid,pem,str(serial),cert.not_valid_before_utc.isoformat(),cert.not_valid_after_utc.isoformat(),"active")); db.commit(); db.close()
        report = verify_certificate(pem, expected_email="mallory@example.com")
        assert not report.valid and not report.subject_ok


def test_revocation_immediately_invalidates_certificate(ca_app):
    with ca_app.app_context():
        init_ca(); _, public_key = generate_rsa_keypair(); pem, serial = issue_user_certificate("Bob Example", "bob@example.com", public_key)
        db = sqlite3.connect(ca_app.config["DATABASE_PATH"])
        db.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)", ("Bob Example", "bob@example.com", "x")); uid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
        cert=x509.load_pem_x509_certificate(pem); db.execute("INSERT INTO certificates (user_id,certificate,serial_number,issued_at,expires_at,status) VALUES (?,?,?,?,?,?)",(uid,pem,str(serial),cert.not_valid_before_utc.isoformat(),cert.not_valid_after_utc.isoformat(),"active")); db.commit(); db.close()
        assert verify_certificate(pem, expected_email="bob@example.com").valid
        assert revoke_certificate(serial)
        report = verify_certificate(pem, expected_email="bob@example.com")
        assert not report.valid and not report.not_revoked


def test_tampered_certificate_and_rogue_ca_are_rejected(ca_app):
    with ca_app.app_context():
        _, public_key = generate_rsa_keypair()
        init_ca(); valid_pem, serial = issue_user_certificate("Carol Example", "carol@example.com", public_key)
        db = sqlite3.connect(ca_app.config["DATABASE_PATH"])
        db.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)", ("Carol Example", "carol@example.com", "x")); uid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
        cert=x509.load_pem_x509_certificate(valid_pem); db.execute("INSERT INTO certificates (user_id,certificate,serial_number,issued_at,expires_at,status) VALUES (?,?,?,?,?,?)",(uid,valid_pem,str(serial),cert.not_valid_before_utc.isoformat(),cert.not_valid_after_utc.isoformat(),"active")); db.commit(); db.close()

        der = bytearray(cert.public_bytes(serialization.Encoding.DER)); der[-1] ^= 1
        tampered = x509.load_der_x509_certificate(bytes(der))
        tampered_pem = tampered.public_bytes(serialization.Encoding.PEM)
        assert not verify_certificate(tampered_pem, expected_email="carol@example.com").valid

        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue")])
        rogue = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(rogue_subject).public_key(public_key).serial_number(cert.serial_number + 1).not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc).sign(rogue_key, hashes.SHA256()))
        assert not verify_certificate(rogue.public_bytes(serialization.Encoding.PEM), expected_email="carol@example.com").valid
