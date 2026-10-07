"""Shared fixtures for the CipherLock test suite.

Centralising fixtures here allows any test module under ``tests/`` to use
them without repeating the setup boilerplate.  Additional phases will extend
this file with fixtures for authenticated sessions, seeded user rows, and
temporary key/certificate directories.
"""
from __future__ import annotations

import pytest

from app import create_app


@pytest.fixture(scope="session")
def _base_config(tmp_path_factory):
    """Return a base configuration dict wired to a temporary directory.

    Using *session* scope avoids recreating the Flask app for every test
    function, which is expensive.  Individual tests that need an isolated
    database should override ``DATABASE_PATH`` with their own ``tmp_path``.
    """
    base = tmp_path_factory.mktemp("cipherlock_session")
    return {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-only-secret-do-not-use-in-production",
        "DATABASE_PATH": base / "cipherlock_test.db",
        "STORAGE_DIR": base / "storage",
        "ENCRYPTED_STORAGE_DIR": base / "storage" / "encrypted",
        "CERTIFICATES_DIR": base / "certificates",
        "CA_CERTIFICATES_DIR": base / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": base / "certificates" / "users",
        "KEYS_DIR": base / "keys",
        "CA_KEYS_DIR": base / "keys" / "ca",
        "USER_KEYS_DIR": base / "keys" / "users",
    }


@pytest.fixture(scope="session")
def session_app(_base_config):
    """Session-scoped Flask application instance for read-only smoke tests."""
    return create_app(_base_config)


@pytest.fixture(scope="session")
def session_client(session_app):
    """Session-scoped test client derived from *session_app*."""
    return session_app.test_client()
