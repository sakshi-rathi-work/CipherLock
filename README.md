# CipherLock

CipherLock is a college Computer Network Security project to design a secure file storage and sharing system. The project is being built in phases so its application foundation can be reviewed before authentication and cryptographic workflows are added.

## Project Overview

The planned system is designed around confidentiality, integrity, sender authentication, secure key management, certificate-based trust, and authorization. These are project goals; the corresponding security workflows are **not implemented in Phase 1**.

### Current Status

**Phase 1 — Foundation**

### Phase 1 Implemented

- Flask application factory, application configuration, CSRF protection, and placeholder route blueprints.
- SQLite connection helpers and reproducible schema initialization.
- Foundation tables for users, files, certificates, and activity records.
- Responsive Bootstrap landing page describing project goals and future security concepts.
- Health endpoint and friendly HTTP error pages.
- Environment-based configuration, ignored local secrets/runtime data, and a persistent generated development secret key.
- Environment diagnostic script and pytest smoke tests.

### Upcoming Phases

| Phase | Planned focus |
| --- | --- |
| 2 | User authentication |
| 3 | RSA key-pair setup and AES-GCM file encryption |
| 4 | Mini certificate authority and X.509 certificates |
| 5 | RSA-OAEP key wrapping and RSA-PSS signatures |
| 6 | Hybrid encrypted file package |
| 7 | Secure file storage and sharing workflows |
| 8 | Recipient verification and decryption |
| 9 | Tampering, revocation, and security demonstrations |
| 10 | Final system integration, testing, and project demonstration (planned) |

All listed work is planned. No later-phase feature should be inferred as currently available.

## Technology Stack

- Python 3.11+
- Flask and Werkzeug (Werkzeug is provided by Flask)
- SQLite using Python's standard `sqlite3` module
- PyCA `cryptography` (dependency for later phases; not used for cryptographic operations in Phase 1)
- Bootstrap 5 via CDN, with HTML/CSS
- Flask-WTF for CSRF protection
- python-dotenv for local environment configuration
- pytest for automated tests

## Project Structure

```text
app.py                    Flask application factory and development entry point
config.py                 Environment-backed configuration and local paths
init_db.py                Database initialization command
database/
  db.py                   SQLite connection lifecycle and initializer
  schema.sql              Versioned Phase 1 schema
routes/                   Placeholder auth, files, users, and admin blueprints
models/                   Reserved for later-phase SQLite helpers
crypto/                   Reserved for later-phase cryptographic modules
templates/                Base layout, landing page, and friendly error pages
static/css/               Project styles
static/js/, static/images/ Reserved static asset directories
scripts/check_env.py      Safe dependency and environment diagnostics
tests/test_app.py         Phase 1 application and schema tests
storage/encrypted/        Reserved encrypted file storage location
certificates/             Reserved CA and user certificate locations
keys/                     Reserved CA and user key locations
docs/                     Project documentation space
```

The app creates required runtime directories at startup. Phase 1 does not generate keys or certificates and does not store file contents.

## Setup

Use Python 3.11 or newer. Create a virtual environment, install dependencies, copy the example environment file, initialize the database, and start Flask.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/check_env.py
python init_db.py
python app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python scripts/check_env.py
python init_db.py
python app.py
```

The landing page is at <http://127.0.0.1:5000/>. The health endpoint is <http://127.0.0.1:5000/health> and returns JSON similar to:

```json
{"status":"ok"}
```

Bootstrap is loaded from jsDelivr, so the page needs internet access to load Bootstrap styling and JavaScript.

## Configuration and Database

`.env.example` lists `SECRET_KEY`, `CIPHERLOCK_CA_PASSPHRASE`, `DEMO_MODE`, and `SESSION_COOKIE_SECURE`. A blank `SECRET_KEY` causes the app to generate a random development key in the ignored `instance/secret_key` file. For deployment, provide `SECRET_KEY` through the environment and enable secure cookies when using HTTPS. Cookies are HttpOnly, SameSite=Lax, and configured for a 30-minute lifetime. The CA passphrase is unused in Phase 1.

Run `python init_db.py` to create `database/cipherlock.db` from `database/schema.sql`. The four tables are:

- `users`: identity and future authentication/key/certificate fields.
- `files`: sender/recipient and future encrypted file package metadata.
- `certificates`: future user certificate, serial, validity, and status data.
- `activity_log`: future user-linked activity records.

The schema defines primary keys, relevant foreign keys, uniqueness/check constraints, timestamps, and indexes. The database file itself is local runtime data and is not intended for Git.

## Testing

Run the tests:

```bash
pytest
```

Or use the interpreter-bound command on Windows:

```powershell
python -m pytest -q
```

Phase 1 verification commands:

```bash
python scripts/check_env.py
python init_db.py
python -m pytest -q
```

The tests cover the landing page, JSON health response, four database tables, and friendly 403/404/413 pages. The expected summary is `6 passed`. `check_env.py` prints installed Python, Flask, and cryptography versions plus whether `.env` and the CA passphrase are set; it does not print their values. To inspect schema tables with the SQLite CLI, run `sqlite3 database/cipherlock.db` and then `.tables` (the CLI is optional; Python's standard library is used by the application).

## Security Notes

- `.env` is ignored and must not be committed; `.env.example` contains placeholders only.
- Generated database and other runtime files are not committed.
- Private keys, CA keys, certificates, and storage contents must remain outside Git.
- Keep all passwords, API keys, passphrases, and other secrets out of source control.
- Cryptographic functionality—including AES-GCM, RSA key operations, signatures, and certificate issuance—is planned for later phases and is not active in this release.
- The built-in Flask server is for local development, not production deployment.
