"""One-command local setup for CipherLock (safe to re-run any time).

    python scripts/setup_dev.py            # first-time setup / health check
    python scripts/setup_dev.py --reset    # wipe local CA + database and start clean

What it does, in order:
  1. Creates ``.env`` from ``.env.example`` if it does not exist.
  2. Generates a random CIPHERLOCK_CA_PASSPHRASE into ``.env`` if it is blank.
  3. Creates the SQLite database tables.
  4. Creates the Root CA, OR verifies that the existing CA key can be opened
     with the passphrase currently in ``.env`` and explains the fix if not.

Why this exists: ``.env``, ``keys/``, ``certificates/`` and the database are
git-ignored on purpose (secrets must never be committed).  Every machine must
therefore have its OWN consistent set.  The classic failure is a CA key that
was encrypted with one passphrase while ``.env`` now holds another.
"""
from __future__ import annotations

import argparse
import re
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
KEY_VAR = "CIPHERLOCK_CA_PASSPHRASE"


def _read_env_value(name: str) -> str:
    if not ENV_FILE.is_file():
        return ""
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        match = re.match(rf"^\s*{name}\s*=\s*(.*)$", line)
        if match:
            return match.group(1).strip().strip("'\"")
    return ""


def _write_env_value(name: str, value: str) -> None:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    replaced = False
    for index, line in enumerate(lines):
        if re.match(rf"^\s*{name}\s*=", line):
            lines[index] = f"{name}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{name}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _reset_local_state() -> None:
    targets = [
        ROOT / "keys" / "ca" / "ca_key.pem",
        ROOT / "certificates" / "ca" / "ca_cert.pem",
        ROOT / "database" / "cipherlock.db",
    ]
    for path in targets:
        if path.exists():
            path.unlink()
            print(f"  removed {path.relative_to(ROOT)}")
    for folder in (ROOT / "certificates" / "users", ROOT / "storage" / "encrypted"):
        if folder.is_dir():
            shutil.rmtree(folder)
            print(f"  removed {folder.relative_to(ROOT)}/")


def main() -> int:
    parser = argparse.ArgumentParser(description="Set up CipherLock for local development.")
    parser.add_argument("--reset", action="store_true",
                        help="delete the local CA, database and stored files first")
    args = parser.parse_args()

    print("CipherLock local setup\n----------------------")

    # Step 1: .env
    if not ENV_FILE.is_file():
        shutil.copyfile(ENV_EXAMPLE, ENV_FILE)
        print("[1/4] Created .env from .env.example")
    else:
        print("[1/4] .env already exists (kept as is)")

    # Optional clean slate (must happen before the app is imported).
    if args.reset:
        print("      --reset: removing local CA, database and stored files")
        _reset_local_state()

    # Step 2: CA passphrase
    passphrase = _read_env_value(KEY_VAR)
    if not passphrase:
        _write_env_value(KEY_VAR, secrets.token_urlsafe(24))
        print(f"[2/4] Generated a random {KEY_VAR} and saved it to .env")
        print("      Keep it: it unlocks keys/ca/ca_key.pem. Never commit .env.")
    elif len(passphrase.encode("utf-8")) < 16:
        print(f"[2/4] ERROR: {KEY_VAR} in .env is shorter than 16 characters.")
        return 1
    else:
        print(f"[2/4] {KEY_VAR} is set")

    # Import AFTER .env is final: config.py reads it at import time.
    from app import create_app
    from crypto.ca import CAConfigurationError, init_ca, load_ca
    from database.db import init_db
    from config import Config

    # Step 3: database
    init_db(Config.DATABASE_PATH)
    print("[3/4] Database ready")

    # Step 4: Root CA
    app = create_app()
    with app.app_context():
        key_path = Path(app.config["CA_KEYS_DIR"]) / "ca_key.pem"
        cert_path = Path(app.config["CA_CERTIFICATES_DIR"]) / "ca_cert.pem"
        if key_path.exists() and cert_path.exists():
            try:
                load_ca()
            except (CAConfigurationError, FileNotFoundError):
                print("[4/4] PROBLEM: the existing CA key cannot be opened with the")
                print(f"      {KEY_VAR} currently in .env (it was created with a different one).")
                print("\n      Fix A: put the ORIGINAL passphrase back in .env.")
                print("      Fix B (local dev): python scripts/setup_dev.py --reset")
                print("             (this deletes the local CA and database; users must re-register)")
                return 1
            print("[4/4] Root CA found and unlocked successfully")
        else:
            _, certificate = init_ca()
            print("[4/4] Root CA created")
            print(f"      Subject: {certificate.subject.rfc4514_string()}")

    print("\nAll good. Start the backend:  python app.py")
    print("Start the frontend (2nd terminal):  cd frontend && npm install && npm run dev")
    return 0


if __name__ == "__main__":
    sys.exit(main())
