"""Initialize the Phase 1 SQLite database from the project root."""
from config import Config
from database.db import init_db

if __name__ == "__main__":
    init_db(Config.DATABASE_PATH)
    print(f"CipherLock database initialized at {Config.DATABASE_PATH}")
