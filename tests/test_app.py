"""Smoke tests for the Phase 1 landing page and health endpoint."""
import sqlite3

import pytest
from flask import abort

from app import create_app


@pytest.fixture
def app(tmp_path):
    database_path = tmp_path / "test_cipherlock.db"
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": database_path,
        "SECRET_KEY": "test-only-secret",
        "STORAGE_DIR": tmp_path / "storage",
        "ENCRYPTED_STORAGE_DIR": tmp_path / "storage" / "encrypted",
        "CERTIFICATES_DIR": tmp_path / "certificates",
        "CA_CERTIFICATES_DIR": tmp_path / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": tmp_path / "certificates" / "users",
        "KEYS_DIR": tmp_path / "keys",
        "CA_KEYS_DIR": tmp_path / "keys" / "ca",
        "USER_KEYS_DIR": tmp_path / "keys" / "users",
    })
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


def test_landing_page_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CipherLock" in response.data
    assert b"These are planned security concepts" not in response.data


def test_health_returns_json(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.is_json
    assert response.get_json() == {"status": "ok"}


def test_database_has_four_contract_tables(app):
    with sqlite3.connect(app.config["DATABASE_PATH"]) as connection:
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "files", "certificates", "activity_log"} <= names


@pytest.mark.parametrize(("path", "status", "message"), [
    ("/_test/403", 403, "403"),
    ("/_test/404", 404, "404"),
    ("/_test/413", 413, "413"),
])
def test_friendly_error_pages(app, client, path, status, message):
    @app.get(path)
    def raise_expected_error():
        abort(status)

    response = client.get(path)
    assert response.status_code == status
    assert message.encode() in response.data
