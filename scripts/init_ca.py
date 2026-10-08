"""Initialize CipherLock's encrypted Root CA."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from crypto.ca import init_ca


if __name__ == "__main__":
    app = create_app()

    with app.app_context():
        _, certificate = init_ca()

        print("CipherLock Root CA initialized successfully.")
        print(f"Subject: {certificate.subject.rfc4514_string()}")
        print(f"Serial: {certificate.serial_number}")
        print(f"Expires: {certificate.not_valid_after_utc.isoformat()}")