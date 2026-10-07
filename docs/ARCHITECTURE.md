# CipherLock – Phase 1 Architecture

> **Status:** Phase 1 Foundation
> **Last updated:** 2026-10

This document describes the structural and design decisions made during Phase 1.
It is a living reference: later phases will extend it to cover authentication,
cryptographic workflows, certificate issuance, and the full file-sharing pipeline.

---

## Overview

CipherLock is a Flask web application that will eventually allow users to
encrypt, store, and securely share files using hybrid cryptography, RSA
key-pairs, and X.509 certificates.  Phase 1 establishes the application
skeleton only: no encryption or authentication is active.

```
Browser ──HTTP──► Flask app (app.py)
                     │
                     ├── config.py          (environment-backed settings)
                     ├── routes/            (placeholder blueprints)
                     ├── database/db.py     (SQLite helpers)
                     ├── database/schema.sql
                     └── templates/         (Jinja2 HTML)
```

---

## Application Factory

`app.py` uses the **application factory pattern** (`create_app`).  This
pattern is recommended by Flask because it:

- Allows multiple application instances with different configurations to
  coexist in the same process (critical for test isolation).
- Defers extension initialisation until the factory is called, which prevents
  circular imports.
- Makes it straightforward to pass a `test_config` dict during testing without
  touching environment variables.

```
create_app(test_config=None)
  │
  ├── app.config.from_object(Config)      # load settings
  ├── [create runtime directories]        # storage, certs, keys
  ├── init_db(...)                        # create tables if absent
  ├── csrf.init_app(app)                  # CSRF protection
  ├── app.teardown_appcontext(close_db)   # connection lifecycle
  └── app.register_blueprint(...)  ×4    # auth, files, users, admin
```

---

## Configuration (`config.py`)

All configuration is centralised in a single `Config` class.  Values are
read from environment variables (`.env` loaded via `python-dotenv`).

| Setting | Source | Purpose |
|---|---|---|
| `SECRET_KEY` | `$SECRET_KEY` or auto-generated | Flask session signing |
| `DATABASE_PATH` | derived from `BASE_DIR` | SQLite file location |
| `STORAGE_DIR` / `ENCRYPTED_STORAGE_DIR` | derived | future encrypted file storage |
| `CERTIFICATES_DIR` / `KEYS_DIR` | derived | future PKI artefacts |
| `MAX_CONTENT_LENGTH` | hardcoded (25 MB) | upload size limit |
| `SESSION_COOKIE_*` | `$SESSION_COOKIE_SECURE` | cookie security settings |
| `PERMANENT_SESSION_LIFETIME` | hardcoded (30 min) | session timeout |
| `CIPHERLOCK_CA_PASSPHRASE` | `$CIPHERLOCK_CA_PASSPHRASE` | future CA key protection |
| `DEMO_MODE` | `$DEMO_MODE` | future demo-user shortcut |
| `WTF_CSRF_TIME_LIMIT` | hardcoded (3600 s) | CSRF token lifetime |

The `_secret_key()` helper ensures that a local development server always has
a **persistent** key (stored in `instance/secret_key`, which is git-ignored)
rather than a new random key on every restart, which would invalidate sessions.

---

## Database Layer

SQLite is used via Python's standard `sqlite3` module.  No ORM is introduced
in Phase 1 to keep dependencies minimal and to keep the schema transparent.

### Schema (`database/schema.sql`)

Four tables are created with `CREATE TABLE IF NOT EXISTS` so the script is
idempotent and safe to run repeatedly:

| Table | Purpose |
|---|---|
| `users` | Identity; future password hash, public key, encrypted private key, certificate |
| `files` | File transfer metadata; future encrypted filename, session key, nonce, signature, status |
| `certificates` | X.509 certificate records; future serial, validity dates, revocation status |
| `activity_log` | Audit trail; future user-linked action records |

Foreign-key enforcement is enabled explicitly with `PRAGMA foreign_keys = ON`.

Six indexes are defined upfront to support the query patterns that will be
introduced in later phases (sender/receiver lookups, status filters,
certificate lookups, and activity-log pagination).

### Connection Lifecycle (`database/db.py`)

| Function | Description |
|---|---|
| `get_db()` | Returns a request-scoped connection stored in Flask's `g` object; enables `foreign_keys` and sets `row_factory = sqlite3.Row` |
| `close_db()` | Registered with `app.teardown_appcontext`; closes the connection at the end of every request |
| `init_db()` | Creates the database file and runs `schema.sql`; safe to call on every startup |

---

## Route Blueprints (`routes/`)

All four blueprints are registered in `create_app` but contain only the
`Blueprint` object in Phase 1.  Routes will be added in subsequent phases.

| Blueprint | Module | Planned responsibility |
|---|---|---|
| `auth_bp` | `routes/auth.py` | Registration, login, logout |
| `files_bp` | `routes/files.py` | Upload, download, list files |
| `users_bp` | `routes/users.py` | Profile, key management |
| `admin_bp` | `routes/admin.py` | User administration, CA operations |

---

## Reserved Directories

| Directory | Purpose |
|---|---|
| `models/` | Future SQLite row-helper classes |
| `crypto/` | Future AES-GCM, RSA, X.509 modules |
| `storage/encrypted/` | Future encrypted ciphertext storage |
| `certificates/ca/` | Future CA certificate |
| `certificates/users/` | Future user certificates |
| `keys/ca/` | Future CA private key (passphrase-protected) |
| `keys/users/` | Future per-user encrypted private keys |

All directories are created at startup by `create_app` so the application
never fails on a missing path.  `.gitkeep` files mark empty directories in
the repository.

---

## Template and Static Asset Layout

```
templates/
  base.html         Shared layout: navbar, flash messages, footer
  index.html        Landing page (extends base.html)
  errors/
    403.html        Forbidden
    404.html        Not Found
    413.html        Request Entity Too Large

static/
  css/
    style.css       Core design tokens and component styles
    landing.css     Entrance-animation layer (driven by main.js)
  js/
    main.js         Smooth-scroll, navbar elevation, IntersectionObserver
                    entrance animations, skip-to-content
  images/           Reserved for future UI images
```

`base.html` loads Bootstrap 5 from jsDelivr (CDN), then the project
stylesheets, and finally `main.js` with `defer` so it never blocks rendering.

---

## Security Posture (Phase 1)

No cryptographic operations are active in Phase 1.  The security measures
that are in place are limited to:

- **CSRF protection** via Flask-WTF (`CSRFProtect`).  All state-changing
  routes in later phases will be protected automatically.
- **HttpOnly, SameSite=Lax cookies** with a 30-minute lifetime.
- **Secret key** never committed to version control; generated locally if
  not supplied via `$SECRET_KEY`.
- **`.env` git-ignored**; only `.env.example` (with placeholder values)
  is committed.
- **Runtime directories and database files git-ignored**.

---

## Testing Strategy

Phase 1 tests are smoke tests that verify the application starts, serves
pages, and creates the expected database schema.

| File | Role |
|---|---|
| `conftest.py` | Session-scoped `app` and `client` fixtures |
| `pytest.ini` | Test discovery, warning filters, output flags |
| `tests/test_app.py` | Landing page (200), health JSON, four DB tables, 403/404/413 pages |

Tests use `tmp_path` / `tmp_path_factory` so the production database is
never touched and tests remain fully isolated from one another.

---

## Planned Phases

| Phase | Focus |
|---|---|
| 2 | User registration and password authentication |
| 3 | RSA key-pair generation and AES-256-GCM file encryption |
| 4 | Mini CA and X.509 certificate issuance |
| 5 | RSA-OAEP session-key wrapping and RSA-PSS signatures |
| 6 | Hybrid encrypted file package assembly |
| 7 | Secure file upload and sharing workflow |
| 8 | Recipient verification and decryption |
| 9 | Tampering detection, certificate revocation, security demonstrations |
| 10 | Final integration, end-to-end testing, and project demonstration |
