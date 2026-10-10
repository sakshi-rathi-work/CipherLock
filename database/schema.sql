PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT,
    public_key BLOB,
    encrypted_private_key BLOB,
    certificate BLOB,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    original_filename TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL UNIQUE,
    encrypted_session_key BLOB,
    nonce BLOB,
    signature BLOB,
    sender_certificate BLOB,
    ciphertext_sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- Phase 7 additive columns (existing databases receive them via
    -- database.db.migrate_files_table; keep both definitions in sync).
    package_version INTEGER NOT NULL DEFAULT 1,
    sender_cert_serial TEXT,
    client_request_id TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    certificate BLOB NOT NULL,
    serial_number TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked'))
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_files_sender_id ON files(sender_id);
CREATE INDEX IF NOT EXISTS idx_files_receiver_id ON files(receiver_id);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
-- Phase 7: stable newest-first listing for the sent and received views.
CREATE INDEX IF NOT EXISTS idx_files_sender_created ON files(sender_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_files_receiver_created ON files(receiver_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_activity_log_user_created ON activity_log(user_id, created_at);
