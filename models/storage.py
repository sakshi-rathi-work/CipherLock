# Handles file storage and retrieval.
"""Encrypted payload storage for CipherLock (Phase 7).

Only AES-256-GCM ciphertext (``ciphertext || 16-byte tag``) is ever written
here. Plaintext never touches disk, and storage paths are never built from
user-supplied names: every payload lives at ``<ENCRYPTED_STORAGE_DIR>/<uuid4>.bin``
and every path is resolved and confined to that directory before use.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from flask import current_app

from crypto.aes import AES_TAG_SIZE

# Exactly what ``new_storage_name`` produces: a lowercase UUID4 plus ``.bin``.
_STORAGE_NAME_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin$"
)
_FILE_MODE = 0o600


class StorageError(Exception):
    """Raised for storage failures; messages never contain filesystem paths."""


class StoredFileMissingError(StorageError):
    """The encrypted payload referenced by a database row does not exist."""


class StoredFileCorruptError(StorageError):
    """The encrypted payload exists but is unusable (e.g. truncated)."""


def storage_dir() -> Path:
    """Return the resolved, existing encrypted-storage directory."""
    directory = Path(current_app.config["ENCRYPTED_STORAGE_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def new_storage_name() -> str:
    """Return a fresh random ``<uuid4>.bin`` storage filename."""
    return f"{uuid.uuid4()}.bin"


def resolve_storage_path(name: str) -> Path:
    """Map a storage filename to an absolute path confined to the storage dir."""
    if not isinstance(name, str) or not _STORAGE_NAME_RE.fullmatch(name):
        raise StorageError("Invalid storage name.")
    base = storage_dir()
    path = (base / name).resolve()
    if path.parent != base:
        raise StorageError("Invalid storage path.")
    return path


def write_ciphertext(name: str, data: bytes) -> None:
    """Atomically persist ciphertext: temp file in the same dir, fsync, rename.

    The temp file is created exclusively (``O_EXCL``) with mode 0600, so no other
    local user can read it even transiently. On any failure the temp file is
    removed and nothing is left at the final path.
    """
    if not isinstance(data, bytes):
        raise TypeError("Ciphertext must be bytes.")
    final_path = resolve_storage_path(name)
    if final_path.exists():
        raise StorageError("Storage name collision.")

    tmp_path = final_path.with_name(f".{final_path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(tmp_path, flags, _FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            tmp_path.chmod(_FILE_MODE)  # best effort; Windows uses ACLs
        except OSError:
            pass
        os.replace(tmp_path, final_path)
    except BaseException:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def delete_ciphertext(name: str) -> bool:
    """Remove a stored payload (used for failure cleanup). Never raises."""
    try:
        resolve_storage_path(name).unlink()
        return True
    except (OSError, StorageError):
        return False


def read_ciphertext(name: str) -> bytes:
    """Read a stored payload, mapping failures to path-free storage errors."""
    path = resolve_storage_path(name)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise StoredFileMissingError("The encrypted payload is missing.") from None
    except OSError:
        raise StorageError("The encrypted payload could not be read.") from None
    if len(data) < AES_TAG_SIZE:
        raise StoredFileCorruptError("The encrypted payload is corrupted.")
    return data


def payload_size(name: str) -> int | None:
    """Return the ciphertext size in bytes, or None if missing/unreadable."""
    try:
        return resolve_storage_path(name).stat().st_size
    except (OSError, StorageError):
        return None


def inspect_payload(name: str, expected_sha256_hex: str | None) -> str:
    """Cheap consistency check used by the metadata endpoint.

    Returns ``"ok"``, ``"missing"`` or ``"corrupted"``. This is *not* the Phase 8
    security verification (certificate + signature); it only reports whether the
    stored bytes still match the digest recorded at upload time.
    """
    try:
        data = read_ciphertext(name)
    except StoredFileMissingError:
        return "missing"
    except StorageError:
        return "corrupted"
    if expected_sha256_hex and hashlib.sha256(data).hexdigest() != expected_sha256_hex:
        return "corrupted"
    return "ok"
