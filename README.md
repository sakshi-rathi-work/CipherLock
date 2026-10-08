# CipherLock

CipherLock is a college Computer Network Security project designing a secure file storage and sharing system (confidentiality, integrity, sender verification, and tamper detection with fail-closed guarantees). The project is built sequentially across 10 structured phases.

## Project Overview

The system is designed around confidentiality, integrity, sender authentication, secure key management, certificate-based trust, and authorization.

### Current Status

**Phase 3 — Crypto Core** (Complete)

### Implemented in Phase 2

- **Secure Password Hashing:** Salted `scrypt` hashing via Werkzeug (`scrypt:` prefix), policy enforcement ($\ge 10$ and $\le 128$ characters, uppercase, lowercase, digit).
- **Authentication API:** REST endpoints under `/api/auth/` for `/register`, `/login`, `/logout`, `/me`, and `/activity`.
- **Brute-Force Lockout:** In-memory tracking per `(email, IP)` pair. 5 consecutive failed attempts trigger a 300-second lockout returning HTTP 429 with `Retry-After`. Non-existent emails are counted identically to prevent username enumeration.
- **Timing Attack Mitigation:** Verification against cached dummy scrypt hash for non-existent users ensures response time parity.
- **Session Management:** Session regeneration on login (`session.clear()` then `session["user_id"]`), HttpOnly + SameSite=Lax cookies, 30-minute idle expiration.
- **Route Decorators:** `@login_required` (validates active user) and `@admin_required` (enforces `is_admin=1`).
- **Activity Auditing:** `models/activity.py` logs `register`, `login`, `login_failed`, `login_locked`, and `logout` without exposing secrets or credentials.
- **CSRF Token API & Protection:** `GET /api/csrf-token` endpoint; CSRF enforced on all mutating HTTP requests.
- **Frontend Authentication SPA (`frontend/`):** React 18 + Vite + Tailwind CSS v3 application continuing Phase 1 design tokens (`--navy`, `--lime`, `--paper`, etc.).
  - Axios client with automatic CSRF token fetching, caching, header injection, and retry.
  - Interactive Register page with real-time password strength meter and rule checklist.
  - Login page with brute-force lockout countdown timer.
  - Dashboard displaying Account profile, active Phase 2 security guarantees, recent activity audit log, and visibly disabled feature tiles for future phases.
- **Automated Tests:** Comprehensive pytest suite with **28 passed tests** (6 Phase 1 + 22 Phase 2).

### Implemented in Phase 1 Foundation

- Flask application factory, configuration, error handling, and directory initialization.
- SQLite schema with 4 contract tables (`users`, `files`, `certificates`, `activity_log`).
- Server-rendered Bootstrap 5 project landing page at `/` and `/health` monitoring endpoint.

### Implemented in Phase 3

- **AES-256-GCM primitives:** `crypto/aes.py` generates 256-bit keys, creates a fresh 96-bit nonce per encryption, returns ciphertext with the GCM tag, and raises `DecryptionError` if authentication fails.
- **RSA-3072 key generation:** `crypto/rsa.py` generates RSA key pairs and serializes public keys as SubjectPublicKeyInfo PEM.
- **Protected private-key storage:** `crypto/key_storage.py` encrypts PKCS#8 private-key PEM with AES-256-GCM. A per-key random salt derives a wrapping key from the existing configured Flask `SECRET_KEY` using HKDF-SHA256; the versioned database envelope stores the salt, nonce, and authenticated ciphertext. The envelope is bound to the owning user ID.
- **Registration provisioning:** `models/provisioning.py` stores the public key and protected private-key envelope within the existing registration transaction. No schema change was needed.
- **Phase 3 tests:** `tests/test_crypto.py` covers AES authentication and round trips, RSA serialization and session-key encryption capability, protected-key recovery/failure, registration storage/exposure, and transaction rollback.

### Upcoming Phases

| Phase | Planned focus | Status |
| --- | --- | --- |
| 1 | Application foundation & schema | `COMPLETE` |
| 2 | User authentication & models | `COMPLETE` |
| 3 | RSA key-pair setup and AES-GCM primitives | `COMPLETE` |
| 4 | Mini certificate authority and X.509 certificates | Next |
| 5 | RSA-OAEP key wrapping and RSA-PSS signatures | Planned |
| 6 | Hybrid encrypted file package | Planned |
| 7 | Secure file storage and sharing workflows | Planned |
| 8 | Recipient verification and decryption | Planned |
| 9 | Tampering, revocation, and security demonstrations | Planned |
| 10 | Final system integration, production serving, and viva | Planned |

## Technology Stack

- **Backend:** Python 3.11+, Flask 3.1.3, Werkzeug, Flask-WTF, python-dotenv, pytest
- **Database:** SQLite 3 with foreign key enforcement
- **Frontend SPA:** React 18, Vite 5, Tailwind CSS v3, Axios, React Router v6, Lucide React, React Hot Toast
- **Public Landing:** Server-rendered Jinja2 + Bootstrap 5 (served at `/`)

## API Endpoints

| Method | Endpoint | Description | Auth Required | CSRF Protected |
| --- | --- | --- | --- | --- |
| `GET` | `/health` | Application health check | No | No |
| `GET` | `/api/csrf-token` | Obtain CSRF synchronizer token | No | No |
| `POST` | `/api/auth/register` | Register new account (`name`, `email`, `password`) | No | Yes |
| `POST` | `/api/auth/login` | Authenticate with `email` and `password` | No | Yes |
| `POST` | `/api/auth/logout` | Terminate session and audit logout | No | Yes |
| `GET` | `/api/auth/me` | Fetch authenticated user profile | Yes | No |
| `GET` | `/api/auth/activity`| Fetch user's recent security audit events | Yes | No |

## Project Structure

```text
app.py                    Flask application factory and API routing
config.py                 Environment-backed configuration and local paths
init_db.py                Database initialization command
database/
  db.py                   SQLite connection lifecycle and initializer
  schema.sql              Versioned SQLite database schema (4 tables)
models/
  user.py                 User CRUD, scrypt hashing, password validation
  activity.py             Security audit logging and activity queries
  lockout.py              In-memory thread-safe brute-force lockout tracker
  provisioning.py         Cryptographic provisioning placeholder hook
routes/
  __init__.py             login_required and admin_required decorators
  auth.py                 Phase 2 authentication REST blueprint (/api/auth)
  files.py, users.py, admin.py  Placeholder blueprints for later phases
frontend/                 React 18 + Vite + Tailwind v3 SPA
  src/api/client.js       Axios client with CSRF token management
  src/context/AuthContext.jsx Authentication state context and hooks
  src/components/         Navbar, Footer, ProtectedRoute, PasswordInput, Spinner
  src/pages/              Register, Login, Dashboard, NotFound
tests/
  test_app.py             Phase 1 baseline tests (6 tests)
  test_auth.py            Phase 2 authentication & security tests (22 tests)
templates/                Phase 1 landing page and error pages
static/                   Phase 1 styles and scripts
scripts/                  Diagnostic and verification scripts
```

## Setup and Running

### 1. Backend Setup

#### Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/check_env.py
python init_db.py
python app.py
```

#### macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python scripts/check_env.py
python init_db.py
python app.py
```

The Flask backend will run at <http://127.0.0.1:5000/>.

### 2. Frontend SPA Setup

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The React frontend development server will run at <http://localhost:5173/>, automatically proxying `/api` requests to Flask.

To build the production frontend bundle:

```bash
cd frontend
npm run build
```

## Running Tests

Run the full automated test suite:

```bash
pytest
```

Or with Python:

```powershell
python -m pytest -v
```

The Phase 3 tests run with:

```bash
python -m pytest tests/test_crypto.py -q
```

Run the complete backend suite with `python -m pytest -q`.

## Security Notes

- Passwords are never stored in plaintext; all password hashes use `scrypt` with random salts.
- Plaintext passwords and private key material never appear in API responses, logs, database files, or session cookies.
- Session cookies are strictly configured with `HttpOnly=True`, `SameSite=Lax`, and 30-minute idle expiration.
- Brute-force lockout enforces a maximum of 5 failed attempts per (email, IP) within a 300-second window.
- CSRF synchronizer tokens are required for all state-mutating requests (`POST`, `PUT`, `DELETE`).
- Parameterized SQL is used across all database queries to prevent SQL injection.
