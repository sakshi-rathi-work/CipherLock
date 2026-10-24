-- Phase 10: Key Management Service (KMS) schema
-- Envelope encryption with versioned KEKs, DEK registry, rotation policies.
PRAGMA foreign_keys = ON;

-- Versioned Key Encryption Keys (KEKs).
-- Each KEK is AES-256-GCM encrypted by the master key (derived from SECRET_KEY).
-- Statuses: 'active' (current), 'rotated' (historical, still usable for decrypt),
--           'compromised' (must rewrap), 'destroyed' (permanently unusable).
CREATE TABLE IF NOT EXISTS kek_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL UNIQUE,
    encrypted_kek   BLOB    NOT NULL,
    nonce           BLOB    NOT NULL,
    salt            BLOB    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'rotated', 'compromised', 'destroyed')),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rotated_at      TEXT,
    expires_at      TEXT,
    compromised_at  TEXT,
    destroyed_at    TEXT,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    description     TEXT    NOT NULL DEFAULT ''
);

-- Per-file Data Encryption Keys (DEKs), wrapped by a specific KEK version.
-- Each file has exactly one DEK entry. On KEK rotation, DEKs are rewrapped
-- (the DEK itself doesn't change, only its wrapping).
CREATE TABLE IF NOT EXISTS dek_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    wrapped_dek     BLOB    NOT NULL,
    nonce           BLOB    NOT NULL,
    kek_version_id  INTEGER NOT NULL REFERENCES kek_versions(id) ON DELETE RESTRICT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rewrapped_at    TEXT,
    UNIQUE(file_id)
);

-- Configurable rotation policies.
CREATE TABLE IF NOT EXISTS rotation_policies (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type            TEXT    NOT NULL UNIQUE CHECK (key_type IN ('kek')),
    rotation_interval_days INTEGER NOT NULL DEFAULT 90,
    auto_rotate         INTEGER NOT NULL DEFAULT 0 CHECK (auto_rotate IN (0, 1)),
    max_versions        INTEGER NOT NULL DEFAULT 10,
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    description         TEXT    NOT NULL DEFAULT ''
);

-- KMS-specific audit log for key lifecycle events.
CREATE TABLE IF NOT EXISTS kms_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT    NOT NULL,
    kek_version     INTEGER,
    detail          TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Indexes for efficient queries.
CREATE INDEX IF NOT EXISTS idx_kek_versions_status ON kek_versions(status);
CREATE INDEX IF NOT EXISTS idx_kek_versions_version ON kek_versions(version);
CREATE INDEX IF NOT EXISTS idx_dek_registry_file_id ON dek_registry(file_id);
CREATE INDEX IF NOT EXISTS idx_dek_registry_kek_version ON dek_registry(kek_version_id);
CREATE INDEX IF NOT EXISTS idx_kms_audit_log_created ON kms_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_kms_audit_log_action ON kms_audit_log(action);

-- Seed default rotation policy if not present.
INSERT OR IGNORE INTO rotation_policies (key_type, rotation_interval_days, auto_rotate, max_versions)
VALUES ('kek', 90, 0, 10);
