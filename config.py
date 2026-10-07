"""Central configuration for the CipherLock Phase 1 Flask application."""
import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
load_dotenv(BASE_DIR / ".env")


def _secret_key() -> str:
    """Load a configured secret, or create a persistent local development key."""
    configured = os.getenv("SECRET_KEY")
    if configured:
        return configured
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    generated = secrets.token_hex(32)
    key_file.write_text(generated, encoding="utf-8")
    try:
        key_file.chmod(0o600)
    except OSError:
        # Windows ACLs govern access; chmod is best effort on other platforms.
        pass
    return generated


class Config:
    SECRET_KEY = _secret_key()
    DATABASE_PATH = (BASE_DIR / "database" / "cipherlock.db").resolve()
    STORAGE_DIR = (BASE_DIR / "storage").resolve()
    ENCRYPTED_STORAGE_DIR = (STORAGE_DIR / "encrypted").resolve()
    CERTIFICATES_DIR = (BASE_DIR / "certificates").resolve()
    CA_CERTIFICATES_DIR = (CERTIFICATES_DIR / "ca").resolve()
    USER_CERTIFICATES_DIR = (CERTIFICATES_DIR / "users").resolve()
    KEYS_DIR = (BASE_DIR / "keys").resolve()
    CA_KEYS_DIR = (KEYS_DIR / "ca").resolve()
    USER_KEYS_DIR = (KEYS_DIR / "users").resolve()
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes"}
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    CIPHERLOCK_CA_PASSPHRASE = os.getenv("CIPHERLOCK_CA_PASSPHRASE", "")
    DEMO_MODE = os.getenv("DEMO_MODE", "0").strip() == "1"
    WTF_CSRF_TIME_LIMIT = 3600
