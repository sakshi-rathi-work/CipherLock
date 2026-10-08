# CipherLock – System Architecture

> **Status:** Phase 3 Complete (AES-GCM and protected RSA keys)
> **Last updated:** 2026-10-08

This document describes the structural and design decisions of CipherLock.
Phase 1 established the application foundation and SQLite schema.
Phase 2 introduced authentication, scrypt password hashing, brute-force lockout,
session management, and the React 18 + Vite + Tailwind v3 SPA (`frontend/`).
Phase 3 adds AES-256-GCM primitives and RSA-3072 user-key provisioning.

```
Browser ──HTTP──► Flask app (app.py) ◄── Vite Proxy (/api) ◄── React SPA (frontend/)
                     │
                     ├── config.py          (environment-backed settings)
                     ├── routes/auth.py     (/api/auth: register, login, logout, me, activity)
                     ├── models/user.py     (scrypt hashing, user CRUD, password policy)
                     ├── models/activity.py (security audit log)
                     ├── models/lockout.py  (in-memory brute-force lockout: 5 fails / 300s)
                     ├── models/provisioning.py (transactional user-key provisioning)
                     ├── crypto/aes.py      (AES-256-GCM byte encryption)
                     ├── crypto/rsa.py      (RSA-3072 generation and PEM serialization)
                     ├── crypto/key_storage.py (versioned AES-GCM private-key envelope)
                     ├── database/db.py     (SQLite helpers with PRAGMA foreign_keys)
                     ├── database/schema.sql
                     └── templates/         (Phase 1 server-rendered Jinja2 landing)
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
| `users` | Identity, scrypt password hash, public key, protected private key, certificate |
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

## Security Posture (Phases 1–3)

AES-GCM encryption/decryption primitives and protected RSA private-key
provisioning are active. Full file encryption/sharing, session-key wrapping
workflow, certificates, and signatures remain future work. Current protections:

- **AES-256-GCM** uses fresh 12-byte nonces and authenticates ciphertext/tag
  during decryption.
- **RSA-3072** private keys are serialized as PKCS#8 in memory and protected
  before persistence with AES-256-GCM. The versioned envelope contains an
  HKDF-SHA256 salt, nonce, and authenticated ciphertext and is bound to its
  user ID.
- **Key derivation** uses the existing configured Flask `SECRET_KEY`, with a
  per-key random salt and distinct HKDF context. Keep that secret stable and
  backed up: rotating it makes existing protected private keys unrecoverable.
- **CSRF protection** via Flask-WTF (`CSRFProtect`) covers state-changing
  routes.
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
| `tests/test_crypto.py` | AES-GCM, RSA serialization, protected private keys, and registration provisioning |

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
