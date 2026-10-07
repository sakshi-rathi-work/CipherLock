"""Print safe environment diagnostics without revealing secret values."""
import importlib.metadata
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass


def version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


print(f"Python: {sys.version.split()[0]}")
print(f"Flask: {version('Flask')}")
print(f"cryptography: {version('cryptography')}")
print(f".env present: {(ROOT / '.env').is_file()}")
print(f"CIPHERLOCK_CA_PASSPHRASE set: {bool(os.getenv('CIPHERLOCK_CA_PASSPHRASE'))}")
