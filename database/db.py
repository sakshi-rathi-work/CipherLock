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


def init_db(database_path: str | Path | None = None) -> None:
    """Create the four Phase 1 contract tables and their useful indexes."""
    if database_path is None:
        from config import Config
        database_path = Config.DATABASE_PATH
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).with_name("schema.sql")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    from config import Config
    init_db(Config.DATABASE_PATH)
    print(f"CipherLock database initialized at {Config.DATABASE_PATH}")
