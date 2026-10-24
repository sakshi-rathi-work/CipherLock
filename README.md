# CipherLock — Secure File Storage and Sharing System

CipherLock is an applied Cryptography and Network Security project (SPIT Mumbai) implementing a secure file storage and sharing web platform with provable cryptographic guarantees: **confidentiality** (AES-256-GCM), **integrity and non-repudiation** (RSA-PSS digital signatures over canonical JSON headers), **sender authenticity and authorization** (X.509 PKI certificates issued by an internal Root CA), and **fail-closed verification** before any file decryption.

The system is developed across 10 sequential, disciplined phases.

---

## Current Status

- **Completed Phases:** Phase 1 through Phase 8 (`COMPLETE`)
- **Current Milestone:** **Phase 8 — Receiver workflow, security status, and in-memory decryption**
- **Next Milestone:** **Phase 9 — Attack demonstrations and admin completion**
- **Test Suite Status:** **158 passed**, 2 skipped (Windows-specific symlink/permission tests), 0 failed
- **CLI Attack Suite:** **9/9 attack cases PASS** (`python scripts/e2e_cli.py`)
- **Frontend SPA Build:** **Clean build** via Vite (`npm run build`)

---

## 10-Phase Project Matrix

| Phase | Milestone | Focus | Status |
| :---: | :--- | :--- | :---: |
| **1** | Application Foundation | Flask app factory, config, SQLite schema, CSRF, security headers, landing page | `COMPLETE` |
| **2** | User Authentication | Salted `scrypt` hashing, brute-force lockout, session management, audit log, React SPA | `COMPLETE` |
| **3** | Cryptographic Primitives | AES-256-GCM authenticated cipher, RSA-3072 key pairs, protected private key envelopes | `COMPLETE` |
| **4** | Mini Public Key Infrastructure | Self-signed RSA-4096 Root CA, X.509 user certificates, fail-closed validation, CA admin | `COMPLETE` |
| **5** | Key Wrapping & Signatures | RSA-OAEP session-key wrapping, RSA-PSS SHA-256 digital signatures with 32-byte salt | `COMPLETE` |
| **6** | Hybrid Cryptographic Package | Canonical JSON header, tamper detection, fail-closed `open_package`, 9 attack CLI proofs | `COMPLETE` |
| **7** | File Storage & Sharing API | In-memory upload stream, random UUID storage, participant-scoped listings, file stats | `COMPLETE` |
| **8** | Receiver Verification & Decryption | 3-panel Security Status UI, monospace audit terminal box, password re-authenticated in-memory download | `COMPLETE` |
| **9** | Attack Demonstrations & Admin | Attacker Simulation Lab (`DEMO_MODE=1`), Stolen Data math proof, CLI attack scripts, admin tools | Planned |
| **10** | Production Hardening & Viva | Security headers, CSP, secret audit script, single-origin serving, report, Viva Q&A | Planned |

---

## Core Cryptographic Architecture (Decisions D1–D8)

CipherLock strictly complies with eight foundational cryptographic principles:

1. **D1 — Hybrid Encryption Standard:** Files are encrypted exclusively with symmetric **AES-256-GCM**. The random 256-bit AES session key is wrapped for the recipient using **RSA-OAEP** (SHA-256, MGF1-SHA-256). The package metadata header is signed with the sender's **RSA-PSS** private key (SHA-256, salt length 32). RSA never directly encrypts files.
2. **D2 — Dedicated RSA-3072 Key Pairs:** Each user possesses a single RSA-3072 key pair. X.509 `KeyUsage` enforces `digitalSignature` and `keyEncipherment`.
3. **D3 — Private Key Protection at Rest:** User private keys are protected as encrypted PKCS#8 envelopes using HKDF-SHA256 derived keys from the application `SECRET_KEY` and bound to the user ID. The user's account password re-authenticates the receiver on download. Keys are never logged, stored in cookies, or sent to client browsers.
4. **D4 — Mini Public Key Infrastructure (PKI):** An internal self-signed RSA-4096 Root CA issues 1-year X.509 user certificates containing CN/email identity, SAN email, and serial numbers tracked in the database with revocation states.
5. **D5 — AES-GCM Authenticated Encryption:** A fresh 32-byte key and 96-bit random nonce are generated per file. Storage format is `ciphertext || 16-byte GCM tag`. Canonical header metadata is authenticated as Additional Authenticated Data (AAD).
6. **D6 — Canonical Signed Header:** Compact, sorted-key JSON:
   ```json
   {"ciphertext_sha256_hex":"...","nonce_b64":"...","original_filename":"...","receiver_id":...,"sender_cert_serial":...,"sender_id":...,"version":1,"wrapped_key_b64":"..."}
   ```
   At verification, `ciphertext_sha256_hex` is **recomputed from the disk ciphertext**, never trusted from the database.
7. **D7 — Fail-Closed Receiver Verification:**
   $$\text{Auth Check} \longrightarrow \text{X.509 CA Trust \& Revocation} \longrightarrow \text{Recomputed SHA-256} \longrightarrow \text{RSA-PSS Signature} \longrightarrow \text{RSA-OAEP Unwrap} \longrightarrow \text{AES-GCM Decrypt}$$
   If any check fails, decryption is refused, returning:
   > *"Signature verification failed. File may have been modified or sender authenticity could not be established."*
8. **D8 — Storage & Memory Discipline:** Plaintext **never touches the server disk or temporary files**. Uploads buffer in `io.BytesIO` via `InMemoryUploadRequest`. Ciphertext files are written with `0600` permissions under random UUIDs (`<uuid4>.bin`). Decrypted files stream directly from memory with `Cache-Control: no-store`.

---

## Detailed Features Implemented by Phase

### Phase 1 — Application Foundation & Database Schema
- Flask application factory (`create_app`) with centralized error handlers (400, 401, 403, 404, 405, 413, 429, 500).
- SQLite database initialization (`database/schema.sql` and `database/db.py`) managing `users`, `files`, `certificates`, and `activity_log` with foreign keys and indexes.
- Responsive server-rendered Bootstrap 5 landing page (`/`) and system `/health` endpoint.
- CSRF synchronizer token protection (`Flask-WTF`).

### Phase 2 — Authentication & Access Control
- Password hashing using salted **`scrypt`** via Werkzeug (`scrypt:` format) with strict complexity validation ($\ge 10$ and $\le 128$ chars, upper, lower, digit).
- Thread-safe in-memory brute-force lockout: 5 consecutive failed login attempts trigger a 300-second lockout window per `(email, IP)` pair.
- Constant-time dummy password verification on unknown email lookups to prevent user enumeration via timing analysis.
- Session regeneration on login (`session.clear()`), `HttpOnly + SameSite=Lax` cookies, 30-minute idle expiration.
- Complete React 18 + Vite + Tailwind CSS v3 SPA (`frontend/`) with live password meter, lockout countdown, and security dashboard.

### Phase 3 — Symmetric & Asymmetric Cryptographic Primitives
- `crypto/aes.py`: AES-256-GCM primitives generating 256-bit keys and 96-bit nonces, with authenticated decryption raising `DecryptionError` on tag mismatch.
- `crypto/rsa.py`: RSA-3072 key pair generation, SubjectPublicKeyInfo PEM serialization, and fingerprint derivation.
- `crypto/key_storage.py`: Encrypted private-key storage envelopes using AES-256-GCM with HKDF-SHA256 key derivation from Flask `SECRET_KEY`, bound to the owning user ID.
- Registration provisioning integration (`models/provisioning.py`) atomically creating keys on user signup.

### Phase 4 — Mini Certificate Authority & X.509 Certificates
- `crypto/ca.py`: RSA-4096 Root CA with encrypted PKCS#8 storage (`CIPHERLOCK_CA_PASSPHRASE`), issuing 1-year X.509 user certificates.
- `crypto/certificates.py`: Fail-closed certificate verification returning structured `CertReport` (evaluating CA signature, validity window, database revocation state, subject email match, and KeyUsage).
- Certificate management endpoints: directory (`/api/users/directory`), certificate viewer (`/api/users/<id>/certificate`), and admin CA panel (`/api/admin/*`).

### Phase 5 — RSA-OAEP Key Wrapping & RSA-PSS Digital Signatures
- `crypto/rsa.py`: `wrap_session_key` and `unwrap_session_key` implementing RSA-OAEP with SHA-256 and MGF1-SHA-256. Raises `UnwrapError` on mismatch to prevent oracle attacks.
- `crypto/signatures.py`: `sign_data` and `verify_signature` implementing RSA-PSS with SHA-256 and 32-byte salt (`PSS_SALT_LENGTH = 32`).
- Helper `sha256_hex` producing 64-character lowercase hexadecimal digests.

### Phase 6 — Hybrid Package Creation & Attack Validation
- `crypto/package.py`: Creates hybrid packages by encrypting with AES-256-GCM, wrapping keys with RSA-OAEP, hashing ciphertext with SHA-256, and signing canonical JSON headers with RSA-PSS.
- Fail-closed verification and opening (`open_package`) raising `TamperError` or `UnwrapError`.
- CLI validation test suite (`scripts/e2e_cli.py`) testing 9 distinct attack vectors against temporary in-memory CA and keys without touching production data.

### Phase 7 — File Storage & Sharing API
- `InMemoryUploadRequest`: Werkzeug stream override ensuring uploaded file plaintext buffers directly in memory (`io.BytesIO`) up to 25 MiB cap.
- Safe ciphertext storage: written atomically via temp files and `os.replace` with `0600` permissions under random UUID filenames (`storage/encrypted/<uuid4>.bin`).
- Additive database migration (`migrate_files_table`) adding `package_version`, `sender_cert_serial`, and `client_request_id` idempotency.
- Participant-scoped endpoints (`/api/files/sent`, `/api/files/received`, `/api/files/<id>`, `/api/files/stats`) with throttled audit logging.

### Phase 8 — Receiver Workflow, Security Status UI & Decryption
- Full receiver verification pipeline (`GET /files/<id>/verify` and `GET /api/files/<id>/verify`):
  - Validates recipient authorization (returns 404 for unauthorized users or senders; fail closed).
  - Reconstructs hybrid package from database record and stored ciphertext on disk.
  - Re-evaluates X.509 certificate trust, recomputes SHA-256 digest from stored `.bin`, and verifies RSA-PSS signature.
  - Updates `files.status` to `verified` or `failed`.
- 3-Panel Security Status UI (`templates/security_status.html` and `frontend/src/pages/SecurityStatus.jsx`):
  - **Certificate Panel:** CA signature, validity dates, revocation status, email binding.
  - **Signature Panel:** RSA-PSS canonical header signature check, signer identity.
  - **Integrity Panel:** SHA-256 digest match between disk ciphertext and signed header.
  - **ASCII Monospace Terminal Status Box:** Exact replica of the CLI `CIPHERLOCK SECURITY CHECK` audit box.
  - **Sender Provenance Card:** Sender name, email, and X.509 certificate serial number.
  - **Decrypt & Download Form:** Active only when overall status is `TRUSTED`.
- In-memory decrypted streaming (`POST /files/<id>/download` and `POST /api/files/<id>/download`):
  - Re-authenticates receiver using their account password.
  - **Unconditionally re-verifies package trust** (never trusts stored database status alone).
  - Unwraps session key via RSA-OAEP, authenticates and decrypts payload via AES-256-GCM in memory.
  - Streams plaintext directly via `send_file(io.BytesIO(plaintext))` with `Cache-Control: no-store` and `Pragma: no-cache`.
  - Fail-closed enforcement: On any failure, returns:
    `"Signature verification failed. File may have been modified or sender authenticity could not be established."`

---

## Route & API Reference

### Web / HTML Routes

| Method | Route | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/` | System overview and security concept landing page | No |
| `GET` | `/health` | Application health check endpoint | No |
| `GET` | `/dashboard` | Receiver dashboard with received transfers and recent audit log | Yes |
| `GET` | `/received` | Secure inbox listing files received by the authenticated user | Yes |
| `GET` | `/files/<id>/verify` | Security Status UI with 3 verification panels and monospace check box | Yes |
| `POST`| `/files/<id>/download`| Password re-authenticated in-memory decryption and streaming download | Yes |

### REST JSON Endpoints

| Method | Endpoint | Description | Auth Required | CSRF Protected |
| :--- | :--- | :--- | :---: | :---: |
| `GET` | `/api/csrf-token` | Fetch synchronizer CSRF token (`Cache-Control: no-store`) | No | No |
| `POST` | `/api/auth/register` | Register new user account with automatic RSA key & X.509 cert provisioning | No | Yes |
| `POST` | `/api/auth/login` | Authenticate with email and password (enforces 5-attempt lockout) | No | Yes |
| `POST` | `/api/auth/logout` | Terminate session and audit logout event | Yes | Yes |
| `GET` | `/api/auth/me` | Return currently authenticated user profile | Yes | No |
| `GET` | `/api/auth/activity` | Return recent security audit logs for the authenticated user | Yes | No |
| `GET` | `/api/users/directory` | Directory of active users with public key fingerprints and cert validity | Yes | No |
| `GET` | `/api/users/<id>/certificate` | Return user X.509 certificate in PEM format with validation report | Yes | No |
| `GET` | `/api/users/<id>/certificate/view` | Return parsed human-readable certificate details and PEM | Yes | No |
| `GET` | `/api/admin/ca-info` | Return Root CA metadata and certificate statistics | Admin | No |
| `GET` | `/api/admin/certificates` | List all issued certificates with status filters | Admin | No |
| `POST` | `/api/admin/certificates/<serial>/revoke` | Revoke a user certificate by serial number | Admin | Yes |
| `POST` | `/api/files/upload` | Multipart upload with hybrid encryption (AES-GCM + OAEP + PSS) | Yes | Yes |
| `GET` | `/api/files/sent` | List files sent by the current user (paginated, searchable) | Yes | No |
| `GET` | `/api/files/received` | List files received by the current user with status badges | Yes | No |
| `GET` | `/api/files/stats` | Return transfer statistics (sent count, received count) | Yes | No |
| `GET` | `/api/files/<id>` | Return transfer metadata and ciphertext storage integrity status | Yes | No |
| `GET` | `/api/files/<id>/verify` | Run full cryptographic verification pipeline and return `SecurityReport` | Yes | No |
| `POST` | `/api/files/<id>/download` | Re-verify package, re-authenticate password, and stream decrypted plaintext | Yes | Yes |

---

## Project Structure

```text
CipherLock/
├── app.py                     # Flask application factory, error handlers, upload streamer
├── config.py                  # Environment-backed configuration, paths, and security limits
├── init_db.py                 # SQLite database initializer and additive schema migrations
├── database/
│   ├── db.py                  # Connection lifecycle, foreign key enforcement, migrations
│   └── schema.sql             # Versioned relational schema (users, files, certificates, activity_log)
├── crypto/
│   ├── aes.py                 # AES-256-GCM encryption/decryption primitives
│   ├── rsa.py                 # RSA-3072 keygen, PEM serialization, RSA-OAEP key wrapping
│   ├── signatures.py          # RSA-PSS SHA-256 digital signatures and SHA-256 hex hashing
│   ├── ca.py                  # Root CA generation, user certificate issuance, revocation
│   ├── certificates.py        # X.509 certificate loading, chain validation, and CertReport
│   ├── package.py             # Canonical JSON header, hybrid package creation, verify, open
│   └── key_storage.py         # Protected user private-key envelope bound to user ID
├── models/
│   ├── user.py                # User CRUD, scrypt password hashing, timing-safe verification
│   ├── file.py                # File metadata CRUD, status updates, package reconstruction
│   ├── activity.py            # Security audit log management and throttled event logging
│   ├── lockout.py             # Thread-safe in-memory brute-force lockout tracker
│   ├── provisioning.py        # Transactional RSA keypair and certificate provisioning
│   └── storage.py             # Safe UUID binary file storage with 0600 permissions
├── routes/
│   ├── __init__.py            # @login_required, @admin_required, current_user helpers
│   ├── auth.py                # Authentication REST API (/api/auth)
│   ├── files.py               # File sharing API (/api/files) and HTML web routes (/received, /verify)
│   ├── users.py               # User directory and certificate inspection (/api/users)
│   └── admin.py               # Root CA management and certificate revocation (/api/admin)
├── templates/                 # Jinja2 server-rendered views
│   ├── base.html              # Base layout with navigation, CSRF injection, and scripts
│   ├── index.html             # System overview landing page
│   ├── dashboard.html         # User dashboard with transfer lists and audit log
│   ├── received_files.html    # Received files inbox with verification badges
│   ├── security_status.html   # 3-panel Security Status screen, ASCII check box, decrypt form
│   ├── partials/
│   │   └── status_badge.html  # Reusable status badge macro (pending, verified, failed)
│   ├── 403.html               # 403 Forbidden error page
│   ├── 404.html               # 404 Not Found error page
│   └── 413.html               # 413 Payload Too Large error page
├── static/
│   ├── css/style.css          # Custom styling and design tokens
│   └── js/app.js              # Password toggles, confirm dialogs, form spinners
├── frontend/                  # React 18 + Vite + Tailwind CSS v3 SPA
│   ├── src/api/client.js      # Axios instance with CSRF management and retry
│   ├── src/components/        # Navbar, Footer, ProtectedRoute, StatusBadge, SecurityBox, SecurityPanel
│   ├── src/pages/             # Register, Login, Dashboard, Directory, CertificateView, SendFile,
│   │                          # SentFiles, ReceivedFiles, SecurityStatus
│   └── package.json           # Frontend dependencies and Vite build scripts
├── tests/                     # Automated pytest suite (160 tests total)
│   ├── test_app.py            # Phase 1 baseline tests (6 tests)
│   ├── test_auth.py           # Phase 2 authentication & lockout tests (22 tests)
│   ├── test_crypto.py         # Phase 3 AES-GCM & RSA tests (8 tests)
│   ├── test_ca_certs.py       # Phase 4 CA & X.509 certificate tests (5 tests)
│   ├── test_signatures.py     # Phase 5 RSA-PSS signature tests (7 tests)
│   ├── test_wrap.py           # Phase 5 RSA-OAEP key wrapping tests (28 tests)
│   ├── test_package.py        # Phase 6 hybrid package roundtrip & attack tests (8 tests)
│   ├── test_files.py          # Phase 7 upload, storage, and participant scoping tests (78 tests)
│   └── test_flow.py           # Phase 8 end-to-end receiver verification & download tests (6 tests)
└── scripts/
    ├── check_env.py           # Environment and dependency diagnostic script
    ├── init_ca.py             # Root CA bootstrap script
    ├── create_admin.py        # Admin account creation script
    ├── demo_wrap_sign.py      # Phase 5 RSA-OAEP and RSA-PSS CLI demo
    └── e2e_cli.py             # Standalone 9-attack cryptographic verification proof
```

---

## Setup and Running

### 1. Environment Configuration

Copy the sample environment file and configure required keys:

```powershell
Copy-Item .env.example .env
```

Ensure `.env` contains:
- `SECRET_KEY`: $\ge 32$ random characters (protects user private key envelopes at rest; must remain stable across restarts).
- `CIPHERLOCK_CA_PASSPHRASE`: $\ge 16$ characters (encrypts the Root CA private key).
- `DEMO_MODE`: `1` (enables demonstration tools; set to `0` for production mode).

### 2. Backend Setup & Database Initialization

```powershell
# Create and activate virtual environment
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run environment sanity check
python scripts/check_env.py

# Initialize database schema and migrations
python init_db.py

# Bootstrap the Root Certificate Authority
python scripts/init_ca.py

# (Optional) Create an admin user account
python scripts/create_admin.py

# Start Flask backend server (http://127.0.0.1:5000)
python app.py
```

### 3. Frontend SPA Setup (React + Vite)

In a separate terminal:

```powershell
cd frontend
npm install
npm run dev
```

The React frontend development server will launch at `http://localhost:5173/`, proxying `/api` requests to Flask at `:5000`.

To build the production frontend bundle:

```powershell
cd frontend
npm run build
```

---

## Testing & Verification

CipherLock includes an exhaustive automated test suite and cryptographic attack verification scripts:

### Run the Complete Automated Test Suite

```powershell
python -m pytest -v
```

*Expected output:* **158 passed, 2 skipped** (Windows file permission tests skipped safely).

### Run Phase 8 End-to-End Receiver Flow Tests

```powershell
python -m pytest tests/test_flow.py -v
```

Tests verify:
1. Complete happy path: Alice sends to Bob $\rightarrow$ Bob verifies (all checks pass, `files.status='verified'`) $\rightarrow$ Bob enters password $\rightarrow$ downloads exact plaintext (SHA-256 matches original byte-for-byte; asserts `Cache-Control: no-store`).
2. Unauthorized user Charlie receives HTTP 404 on both verify and download attempts.
3. Incorrect password blocks download with HTTP 401 error.
4. Tampered ciphertext (1 flipped byte) causes verification failure and blocks download with exact message: *"Signature verification failed. File may have been modified or sender authenticity could not be established."*
5. Sender cannot download their own file (HTTP 404).
6. Revoked sender certificate causes verification failure and blocks download.

### Run Cryptographic Package Attack Suite (9 Scenarios)

```powershell
python scripts/e2e_cli.py
```

*Expected output:* **PASS — 9/9 attack cases matched** (tampered ciphertext, altered filename, altered recipient ID, forged signature, rogue CA cert, expired cert, revoked cert, wrong recipient private key, attacker without private key).
