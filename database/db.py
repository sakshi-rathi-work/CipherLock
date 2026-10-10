"""SQLite lifecycle and Phase 1 schema initialization helpers."""
import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    """Get a request-scoped connection with foreign key enforcement enabled."""
    if "db" not in g:
        path = Path(current_app.config["DATABASE_PATH"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    """Close the request-scoped connection at the end of the app context."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


# Phase 7 additive columns on ``files``. ALTER TABLE ... ADD COLUMN is the
# smallest SQLite migration that preserves every existing row.
#   package_version     - signed-header ``version`` field (Phase 6 PACKAGE_VERSION)
#   sender_cert_serial  - signed-header ``sender_cert_serial`` (TEXT: serials are
#                         ~159-bit integers that overflow SQLite's INTEGER)
#   client_request_id   - optional client idempotency key for upload retries
_FILES_PHASE7_COLUMNS = (
    ("package_version", "INTEGER NOT NULL DEFAULT 1"),
    ("sender_cert_serial", "TEXT"),
    ("client_request_id", "TEXT"),
)


def migrate_files_table(connection: sqlite3.Connection) -> list[str]:
    """Idempotently upgrade the ``files`` table to the Phase 7 shape.

    Safe to run repeatedly and on databases created by Phases 1-6: existing
    rows, users, certificates and activity logs are never dropped or rewritten
    (apart from back-filling ``sender_cert_serial`` from the stored sender
    certificate). Returns the names of the columns added by this call.
    """
    existing = {row[1] for row in connection.execute("PRAGMA table_info(files)")}
    added: list[str] = []
    for name, definition in _FILES_PHASE7_COLUMNS:
        if name in existing:
            continue
        try:
            connection.execute(f"ALTER TABLE files ADD COLUMN {name} {definition}")
            added.append(name)
        except sqlite3.OperationalError as exc:
            # A concurrent process may have added the column first.
            if "duplicate column name" not in str(exc).lower():
                raise

    # One logical upload per (sender, idempotency key); NULL keys are unconstrained.
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_files_sender_request "
        "ON files(sender_id, client_request_id) WHERE client_request_id IS NOT NULL"
    )

    _backfill_sender_cert_serial(connection)
    return added


def _backfill_sender_cert_serial(connection: sqlite3.Connection) -> None:
    """Best-effort: derive ``sender_cert_serial`` for rows that predate Phase 7."""
    rows = connection.execute(
        "SELECT id, sender_certificate FROM files "
        "WHERE sender_cert_serial IS NULL AND sender_certificate IS NOT NULL"
    ).fetchall()
    if not rows:
        return
    from cryptography import x509

    for row in rows:
        try:
            serial = x509.load_pem_x509_certificate(bytes(row[1])).serial_number
        except (TypeError, ValueError):
            continue  # Leave NULL; Phase 8 treats such a package as unverifiable.
        connection.execute(
            "UPDATE files SET sender_cert_serial = ? WHERE id = ?", (str(serial), row[0])
        )


def init_db(database_path: str | Path | None = None) -> None:
    """Create the contract tables/indexes and apply additive migrations (idempotent)."""
    if database_path is None:
        from config import Config
        database_path = Config.DATABASE_PATH
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).with_name("schema.sql")
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema_path.read_text(encoding="utf-8"))
        migrate_files_table(connection)
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    from config import Config
    init_db(Config.DATABASE_PATH)
    print(f"CipherLock database initialized at {Config.DATABASE_PATH}")
