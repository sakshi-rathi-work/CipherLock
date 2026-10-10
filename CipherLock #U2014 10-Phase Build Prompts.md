# CipherLock — 10-Phase Build Prompts

Secure File Storage and Sharing System · Cryptography and Network Security · SPIT Mumbai

## How to use this document

- Each phase below is ONE complete prompt inside a grey code block. Copy the whole block and paste it into any AI chat (new chat or the same one). It already contains the full project description, the fixed design decisions, the module contract, and the exact output format, so the AI starts generating files immediately.
- Do the phases in order, 1 to 10. Do not skip. After each phase, run the tests given in that phase, and only then move on.
- If you paste a later phase into a brand-new chat, also paste your current code files from earlier phases (at least the files that phase lists under "Depends on"). If you cannot, the prompt tells the AI to create minimal stubs from the module contract so the phase still runs.
- If something errors, paste the full error plus the file it came from back to the AI and say "fix this, give me the complete corrected file".
- Every phase repeats the same project context and the same fixed design decisions on purpose, so every phase produces code that fits together.

## Roadmap

1. Phase 1 — Foundation: project skeleton, config, database, landing page
2. Phase 2 — Authentication: register, login, sessions, password hashing
3. Phase 3 — Crypto core: AES-256-GCM and RSA key generation, protected private keys
4. Phase 4 — Mini CA and X.509 certificates, certificate verification, admin CA panel
5. Phase 5 — RSA-OAEP key wrapping and RSA-PSS digital signatures
6. Phase 6 — Hybrid secure package: encrypt + wrap + sign + verify + open (CLI proof)
7. Phase 7 — Secure upload, storage and sharing, sent files, authorization
8. Phase 8 — Receiver workflow: verification, security-status UI, decryption and download
9. Phase 9 — Attack demos: tampering, unauthorized access, revocation, admin completion
10. Phase 10 — Hardening, full testing, README, diagrams, report, PPT, viva, demo script

## Phase 1 — Foundation

Goal: runnable Flask app, folder structure, config, full database schema, landing page and base template.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 1 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 1 OF 10 — FOUNDATION
Depends on: nothing.

Build these files:
- requirements.txt (Flask, cryptography, python-dotenv, Flask-WTF, pytest; pin sensible versions)
- .env.example (SECRET_KEY, CIPHERLOCK_CA_PASSPHRASE, DEMO_MODE=0) and .gitignore (ignore .env, keys/, storage/, certificates/, database/*.db, venv, __pycache__)
- config.py: load .env; SECRET_KEY from env, else generate once with secrets.token_hex and save to instance/secret_key (never hardcode); absolute paths for DB, storage, certificates, keys; MAX_CONTENT_LENGTH = 25 MB; session cookie HttpOnly + SameSite=Lax (Secure flag switchable); 30-minute session lifetime.
- app.py: Flask app factory create_app(); CSRFProtect; register blueprints auth, files, users, admin (empty blueprints are fine now); route / (landing page) and /health returning JSON {status:"ok"}; error handlers for 403, 404, 413 with friendly pages; create all folders on startup if missing.
- database/db.py (or init_db.py): get_db(), close_db(), init_db() creating ALL four tables exactly per the module contract with foreign keys and sensible indexes; python init_db.py initializes the DB.
- templates/base.html: Bootstrap 5 navbar (CipherLock brand, links change by login state), flash-message area, footer; templates/index.html landing page with project name, short description, and 6 security feature cards (AES-256-GCM, RSA-OAEP key protection, RSA-PSS signatures, X.509 + mini CA, tamper detection, secure sharing); static/css/style.css with a clean, professional dark-blue theme; templates/errors for 403/404/413.
- scripts/check_env.py: prints Python version, installed cryptography and Flask versions, and whether .env and CIPHERLOCK_CA_PASSPHRASE are set.
- Create every empty folder in the tree with a .gitkeep where needed.

Test: python scripts/check_env.py; python init_db.py; run the app; open http://127.0.0.1:5000/ and /health; confirm the four tables exist with sqlite3 and the .tables command. Include tests/test_app.py (pytest) checking / returns 200 and /health returns JSON.
Now start generating Phase 1.
```

## Phase 2 — Authentication

Goal: registration, login, logout, secure password storage, sessions, activity log.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 2 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 2 OF 10 — AUTHENTICATION AND DATABASE MODELS
Depends on: Phase 1 (config.py, app.py, database/db.py, base.html, schema).

Build or modify these files:
- models/user.py: create_user, get_user_by_email, get_user_by_id, list_other_users(exclude_id), set_user_active; all queries parameterized (no string-formatted SQL, to prevent SQL injection). models/activity.py (or inside user.py): log_activity(user_id, action, detail) — never log passwords, keys or tokens.
- routes/auth.py: /register, /login, /logout. Password policy: at least 10 characters with upper, lower and digit. Hash with Werkzeug generate_password_hash (scrypt); never store plaintext. Generic login error "Invalid email or password" (no user enumeration). Simple in-memory brute-force protection: 5 failed attempts per email+IP triggers a 5-minute lockout. Clear and re-create the session on login; session holds only user_id. login_required and admin_required decorators in routes/__init__.py (or a decorators.py). Check is_active at login.
- Hook for later phases: in registration call provision_user_crypto(user_id, name, email, password) defined in models/provisioning.py. For now it is a clearly commented placeholder (does nothing); Phase 3 adds RSA keys and Phase 4 adds the certificate.
- templates/register.html and login.html (Bootstrap forms, CSRF token, client-side validation, password strength hint); templates/dashboard.html placeholder showing welcome, counts (0 for now) and recent activity from activity_log; navbar updates by login state.
- tests/test_auth.py: register ok; duplicate email rejected; weak password rejected; wrong password rejected; correct login works; protected page redirects when logged out; password_hash in DB starts with "scrypt:" and never equals the password.

Explain: why salted slow hashing (scrypt) beats plain SHA-256 for passwords, what CSRF is and how the token stops it, and why the login message is generic.
Test: run pytest; register two users (Siddharth and Vidhi) in the browser; inspect the DB with sqlite3 to show only hashes are stored.
Now start generating Phase 2.
```

## Phase 3 — Crypto core: AES-256-GCM and RSA key generation

Goal: independent, tested AES-256-GCM module and RSA key generation with encrypted private keys; keys created at registration.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 3 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 3 OF 10 — CRYPTO CORE: AES-256-GCM AND RSA KEY PAIRS
Depends on: Phases 1-2 (registration route and models/provisioning.py hook).

Build or modify these files:
- crypto/aes.py: generate_session_key() using AESGCM.generate_key(bit_length=256); encrypt_bytes(key, plaintext, aad) generating a fresh 12-byte nonce with os.urandom, returning (nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad) raising a clear custom exception (e.g. DecryptionError) on cryptography.exceptions.InvalidTag. Validate key length is 32 bytes. Comment why nonce reuse under one key is catastrophic for GCM and why AAD is used.
- crypto/rsa.py (this phase only): generate_rsa_keypair(bits=3072, public_exponent=65537); private_key_to_encrypted_pem(priv, passphrase) using PKCS8 + BestAvailableEncryption; load_private_key(pem, passphrase) raising a clear error on wrong passphrase; public_key_to_pem(pub); load_public_key(pem); public_key_fingerprint(pub) (SHA-256 hex of DER SubjectPublicKeyInfo). Leave wrap/unwrap for Phase 5.
- models/provisioning.py: fill provision_user_crypto so registration now generates the RSA-3072 pair, stores public_key PEM and encrypted_private_key PEM (passphrase = the registration password) in the users row. Certificate comes in Phase 4 (leave a clearly marked TODO call). Tell the user key generation takes a couple of seconds and show a "Generating your keys..." message in register.html with a small JS spinner.
- scripts/demo_aes.py: CLI that encrypts any file with AES-256-GCM, prints key size, nonce hex, tag hex, ciphertext length, then decrypts and compares SHA-256 of original and result.
- tests/test_aes.py: round trip; ciphertext differs from plaintext; flipping 1 byte of ciphertext raises DecryptionError; wrong key fails; wrong AAD fails; 1,000 encryptions give 1,000 distinct nonces; key length is exactly 32 bytes.
- tests/test_rsa_keys.py: key size 3072; encrypted PEM header is "BEGIN ENCRYPTED PRIVATE KEY"; correct passphrase loads; wrong passphrase fails; public PEM never contains "PRIVATE".

Explain: symmetric vs asymmetric, why AES-GCM is authenticated encryption, what the 16-byte tag proves, why the private key is encrypted at rest and what the passphrase does, and why 3072-bit RSA and exponent 65537.
Test: pytest; python scripts/demo_aes.py sample.txt; register a user and confirm in sqlite3 that users.encrypted_private_key starts with "-----BEGIN ENCRYPTED PRIVATE KEY-----".
Now start generating Phase 3.
```

## Phase 4 — Mini CA and X.509 certificates

Goal: Root CA, certificate issuance at registration, certificate verification, basic admin CA panel.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 4 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 4 OF 10 — MINI CA AND X.509 CERTIFICATES
Depends on: Phases 1-3 (crypto/rsa.py, models/provisioning.py, users table).

Build or modify these files:
- crypto/ca.py: init_ca() creates the RSA-4096 self-signed Root CA (Subject CN=CipherLock Root CA, O=CipherLock, C=IN), 10-year validity, BasicConstraints(ca=True, path_length=0), KeyUsage(key_cert_sign, crl_sign), SubjectKeyIdentifier; writes the encrypted key to keys/ca/ca_key.pem (passphrase from CIPHERLOCK_CA_PASSPHRASE; raise a clear error if unset; file mode 0600) and the certificate to certificates/ca/ca_cert.pem. load_ca() loads both. issue_user_certificate(name, email, public_key, days=365, not_before=None) builds an X.509 v3 certificate signed by the CA with SHA-256 + RSA PKCS#1 v1.5 (X.509 standard signature), random unique serial, Subject CN=name + emailAddress=email, SAN email, KeyUsage(digital_signature, key_encipherment), BasicConstraints(ca=False), AuthorityKeyIdentifier, SubjectKeyIdentifier; returns (cert_pem, serial). revoke_certificate(serial) sets certificates.status = revoked.
- crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None) returning a CertReport dataclass with ca_signature_ok (verify the CA public key signature over tbs_certificate_bytes with the certificate's own hash algorithm), validity_ok (not_valid_before <= now <= not_valid_after, timezone-aware UTC), not_revoked (certificates table lookup by serial), subject_ok (emailAddress matches expected_email when given), key_usage_ok (digital_signature and key_encipherment present, not a CA cert), valid (all true) and reason (human-readable first failure).
- scripts/init_ca.py (run once; refuses to overwrite an existing CA unless --force), scripts/create_admin.py (creates an admin user with keys and certificate, is_admin=1).
- models/provisioning.py: now also issues the user's certificate, stores it in users.certificate, inserts a row into certificates (serial, issued_at, expires_at, status=active) and exports a copy to certificates/users/<id>.pem.
- routes/users.py: /users/directory (logged-in users see name, email, certificate serial, fingerprint, status — never private material); /users/<id>/certificate downloads the PUBLIC certificate PEM; /users/<id>/certificate/view shows decoded fields.
- routes/admin.py + templates/admin.html (admin_required): CA info (subject, validity, SHA-256 fingerprint), table of all user certificates with status, revoke button (POST + CSRF), user list. Normal users get 403.
- tests/test_ca_certs.py using a temporary CA directory: valid cert verifies; cert issued by a different rogue CA fails ca_signature_ok; expired cert (issue with past not_before and days) fails validity_ok; revoked cert fails not_revoked; wrong expected_email fails subject_ok; tampering one byte of the cert DER fails.

Explain: what an X.509 certificate contains, how a CA signature creates trust, what a chain of trust is, why the CA key must be protected, and why PKCS#1 v1.5 is still used for certificate signatures while PSS is used for our file signatures.
Test: set CIPHERLOCK_CA_PASSPHRASE; python scripts/init_ca.py; pytest; register a user; run openssl x509 -in certificates/users/1.pem -text -noout and openssl verify -CAfile certificates/ca/ca_cert.pem certificates/users/1.pem (expected: OK).
Now start generating Phase 4.
```

## Phase 5 — RSA-OAEP key wrapping and RSA-PSS signatures

Goal: finish crypto/rsa.py and add crypto/signatures.py, each fully unit-tested on its own.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 5 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 5 OF 10 — RSA-OAEP KEY WRAPPING AND RSA-PSS SIGNATURES
Depends on: Phase 3 (crypto/rsa.py, crypto/aes.py).

Build or modify these files:
- crypto/rsa.py (extend, keep earlier functions unchanged): wrap_session_key(public_key, session_key) using padding.OAEP(mgf=MGF1(SHA256), algorithm=SHA256, label=None); validate session_key is 32 bytes. unwrap_session_key(private_key, wrapped) raising a clear custom UnwrapError on failure (wrong key or damaged data) and never revealing details.
- crypto/signatures.py: sign_data(private_key, data) using padding.PSS(mgf=MGF1(SHA256), salt_length=32) with SHA256; verify_signature(public_key, data, signature) returning True/False (catch InvalidSignature; never raise on a bad signature). Add sha256_hex(data).
- scripts/demo_wrap_sign.py: generates two users (Siddharth, Vidhi) in memory; generates a random AES key; wraps it for Vidhi; prints wrapped length (384 bytes for RSA-3072); shows that wrapping the same key twice gives different outputs (OAEP is randomized); Vidhi unwraps and the keys match; Siddharth's key and an attacker's key fail; Siddharth signs a message; Vidhi verifies it with Siddharth's public key (True); one flipped bit makes it False; signing twice gives different signatures (PSS is randomized) that both verify. Print a clean labeled report.
- tests/test_wrap.py and tests/test_signatures.py covering every case in the demo plus: wrong private key fails to unwrap, wrapping a 31-byte key is rejected, signature by user A does not verify under user B's public key, empty data can be signed and verified.

Explain with baby steps: the maximum OAEP message size formula (k - 2*hLen - 2 = 384 - 64 - 2 = 318 bytes for RSA-3072 with SHA-256, so a 32-byte key fits), why OAEP not PKCS#1 v1.5 (padding-oracle attacks), why PSS not PKCS#1 v1.5 signatures (probabilistic, provable security), what the hash does in signing, and why encrypting with the recipient's PUBLIC key and signing with the sender's PRIVATE key are opposite operations.
Test: pytest; python scripts/demo_wrap_sign.py with the expected labeled output.
Now start generating Phase 5.
```

## Phase 6 — Hybrid secure package (end-to-end crypto proof in CLI)

Goal: crypto/package.py joins everything; prove the whole cryptographic flow and every tamper case WITHOUT the web UI.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 6 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 6 OF 10 — HYBRID SECURE PACKAGE
Depends on: Phases 3, 4, 5 (aes, rsa, signatures, ca, certificates).

Build or modify these files:
- crypto/package.py:
  * canonical_header(version, sender_id, receiver_id, original_filename, nonce, wrapped_key, ciphertext_sha256_hex, sender_cert_serial) -> bytes exactly per D6 (json.dumps with sort_keys=True, separators=(",", ":"), ensure_ascii=True, UTF-8; nonce and wrapped key as base64 text).
  * build_package(plaintext, original_filename, sender_id, receiver_id, sender_private_key, sender_cert_pem, receiver_public_key) -> dict containing ciphertext_with_tag, nonce, wrapped_key, signature, ciphertext_sha256_hex, sender_cert_pem, header fields. Order: generate AES key -> compute AAD (canonical header WITHOUT the ciphertext hash and WITHOUT the wrapped key, documented clearly: version, sender_id, receiver_id, original_filename, sender_cert_serial) -> AES-GCM encrypt -> hash the ciphertext -> RSA-OAEP wrap -> build the full canonical header -> RSA-PSS sign -> drop the key variable.
  * verify_package(package, expected_sender_email=None) -> SecurityReport dataclass with certificate ("VALID"/"INVALID"), signature ("VALID"/"INVALID"), integrity ("PASSED"/"FAILED"), overall ("TRUSTED"/"POSSIBLE TAMPERING"/"UNTRUSTED SENDER"), messages (list of reasons). Steps: verify the sender certificate via crypto/certificates.py; RECOMPUTE SHA-256 of the actual stored ciphertext; rebuild the canonical header from the package fields and the recomputed hash; verify the RSA-PSS signature with the public key from the certificate. Integrity = PASSED only if the recomputed hash equals the recorded hash AND the signature is valid. A tampered ciphertext therefore shows: Certificate VALID, Signature INVALID, Integrity FAILED.
  * open_package(package, receiver_private_key) -> bytes: refuses to run if verify_package overall is not TRUSTED (raise a clear TamperError); then unwrap the key and AES-GCM decrypt with the same AAD; a GCM tag failure is a second line of defense.
  * format_security_box(report) -> string printing exactly:
    --------------------------------
    CIPHERLOCK SECURITY CHECK
    --------------------------------
    Certificate: VALID
    Signature: INVALID
    Integrity: FAILED
    Status: POSSIBLE TAMPERING
    --------------------------------
- scripts/e2e_cli.py: in a temp directory create a temp CA, two users (Siddharth, Vidhi) with keys and certificates, encrypt a sample file, verify, decrypt, compare SHA-256 with the original and print the box. Then run and print results for ALL attack cases: (1) flip one byte of ciphertext, (2) change original_filename in the header, (3) change receiver_id, (4) replace the signature with one made by another user, (5) swap in a certificate issued by a rogue CA, (6) expired sender certificate, (7) revoked sender certificate, (8) wrong recipient private key tries to open (UnwrapError), (9) attacker holding ciphertext + wrapped key + signature + certificate but no private key. Finish with a PASS/FAIL table of expected vs actual.
- tests/test_package.py asserting all nine cases plus the happy path with a 5 MB random file.

Explain with baby steps: exactly which bytes the signature covers and why, why we sign the ciphertext hash, the wrapped key and the recipient id (prevents swapping them), why AAD binds metadata to the ciphertext, and why the receiver verifies BEFORE decrypting (never process untrusted data).
Test: pytest; python scripts/e2e_cli.py with the expected output.
Now start generating Phase 6.
```

## Phase 7 — Secure upload, storage and sharing

Goal: web upload flow that encrypts, wraps, signs and stores; sent files page; dashboard counts; authorization.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 7 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 7 OF 10 — SECURE UPLOAD, STORAGE AND SHARING
Depends on: Phases 1-6 (auth, keys, CA, crypto/package.py).

Build or modify these files:
- models/file.py: create_file_record(...), list_sent(user_id), list_received(user_id), get_file_for_receiver(file_id, user_id), get_file_for_sender(file_id, user_id), update_status(file_id, status), count_sent/received. Authorization lives here: a file is returned only if user_id is its sender (metadata only) or its receiver; otherwise return None and the route answers 404 (do not reveal that the file exists). All queries parameterized.
- routes/files.py: GET/POST /upload. Form: file picker, recipient dropdown (list_other_users, only active users with a currently valid certificate; the sender cannot choose themselves), and a password field to unlock the sender's private key. Server-side checks: login required; file present and non-empty; size <= 25 MB (also 413 handler); filename cleaned with secure_filename and length-limited; recipient exists and their certificate passes verify_certificate BEFORE wrapping; password correct (check_password_hash) and the private key loads. Then: read file bytes in memory -> build_package(...) -> write ciphertext_with_tag to storage/encrypted/<uuid4>.bin (mode 0600, write to temp name then os.replace so partial files never appear) -> insert the files row (status="pending_verification") -> log_activity (filename and recipient id only, never keys) -> flash a success summary listing AES-256-GCM, RSA-OAEP, RSA-PSS and the SHA-256 of the ciphertext. Wipe sensitive variables where practical. Never write plaintext to disk. On any crypto failure show a clear message and store nothing.
- GET /sent: sent_files.html table with filename, recipient, encryption status ("AES-256-GCM encrypted"), signature status ("RSA-PSS signed"), date/time, and the file's current verification status. No decrypt link on the sender side.
- templates/upload.html (Bootstrap form, selected-file name and size preview, a step list that visually shows the pipeline Encrypt -> Wrap key -> Sign -> Store, loading state on submit, CSRF token) and templates/sent_files.html.
- dashboard.html + route: counts of sent and received files, last 5 activity entries, status of the user's own certificate (valid/expiry date).
- tests/test_upload.py using the Flask test client with two registered users: upload ok -> a .bin exists, its bytes differ from the plaintext and do not contain the plaintext; DB row exists with non-empty signature, nonce, wrapped key; wrong password rejected and nothing stored; empty file rejected; oversized file rejected; recipient who is revoked is rejected; a third user cannot see the file in any list; unauthenticated upload redirects to login.

Explain with baby steps: the exact order of operations during upload and why each step is where it is, why the recipient's certificate is verified before encrypting for them, why the sender can never decrypt the file again (the AES key is wrapped only for the recipient), why the stored name is random, and what atomic file writes protect against.
Test: run the app with two users in two different browsers (or one normal window and one private window); upload sample.pdf from Siddharth to Vidhi; look at storage/encrypted with a hex viewer and confirm no readable text; inspect the DB row with sqlite3.
Now start generating Phase 7.
```

## Phase 8 — Receiver workflow, security status and decryption

Goal: received files list, full verification pipeline with a security-status screen, and decrypt/download only after verification passes.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 8 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 8 OF 10 — RECEIVER WORKFLOW, SECURITY STATUS AND DECRYPTION
Depends on: Phases 1-7 (models/file.py, routes/files.py, crypto/package.py).

Build or modify these files:
- routes/files.py (extend): GET /received lists the logged-in user's received files (filename, sender name and email, date, current status badge, buttons Verify and Decrypt). GET /files/<id>/verify loads the file only via get_file_for_receiver (404 otherwise), rebuilds the package from the DB row plus the stored .bin, runs verify_package with expected_sender_email = the sender's registered email, saves the outcome to files.status (verified / failed) and logs it, and renders security_status.html. POST /files/<id>/download (CSRF + password field): re-runs verification (never trust an earlier result), and ONLY if overall is TRUSTED loads the receiver's private key with the entered password, calls open_package, and streams the plaintext from memory with send_file(BytesIO(...), as_attachment=True, download_name=original_filename). If verification fails show exactly: "Signature verification failed. File may have been modified or sender authenticity could not be established." and decrypt nothing. Wrong password -> clear error, no file. Catch TamperError, UnwrapError and DecryptionError separately with distinct, safe messages. Set Cache-Control: no-store on the download response.
- templates/security_status.html: three large panels CERTIFICATE (VALID/INVALID), SIGNATURE (VALID/INVALID), INTEGRITY (PASSED/FAILED) with green/red badges and icons; under each a list of the individual checks (CA signature, validity period, not revoked, subject matches sender, key usage, hash recomputed, PSS signature) with tick or cross; a monospace box that reproduces exactly:
  --------------------------------
  CIPHERLOCK SECURITY CHECK
  --------------------------------
  Certificate: VALID
  Signature: VALID
  Integrity: PASSED
  Status: TRUSTED
  --------------------------------
  plus sender details (name, email, certificate serial, SHA-256 fingerprint) and a Decrypt and Download form that appears only when overall is TRUSTED.
- templates/received_files.html, templates/partials/status_badge.html (reusable badge macro), dashboard.html updated with a verification-status column for received files and recent activity; static/js/app.js for confirm dialogs and loading spinners.
- tests/test_flow.py using the Flask test client: happy path A -> B returns bytes identical to the original; user C gets 404 on verify and download of A -> B's file; B with a wrong password cannot download; flipping a byte in the stored .bin makes verify show Signature INVALID / Integrity FAILED and download is refused with the exact failure message; the sender cannot download their own file.

Explain with baby steps: the receiver pipeline from D7 stage by stage and what each stage proves (authorization = who may ask, certificate = who the sender is, signature = what they sent is unchanged, unwrap = only the recipient's key opens it, GCM = final integrity check), why verification is repeated on every download, and why we stream the plaintext from memory instead of saving it.
Test: full browser demo Siddharth -> Vidhi: upload, Vidhi verifies (green), decrypts, downloaded file hash equals the original (show Get-FileHash on Windows or shasum -a 256 on macOS/Linux).
Now start generating Phase 8.
```

## Phase 9 — Attack demonstrations and admin completion

Goal: tampering demo, unauthorized-access demo, revocation and expiry demos, attacker simulation lab, finished admin panel.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 9 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 9 OF 10 — ATTACK DEMONSTRATIONS AND ADMIN COMPLETION
Depends on: Phases 1-8 (full working upload/verify/decrypt flow).

Build or modify these files:
- routes/admin.py + templates/admin_lab.html: an "Attacker Simulation Lab" available ONLY when DEMO_MODE=1 in .env AND the user is an admin (otherwise 404). It lists existing shared files and offers POST + CSRF buttons: (1) Tamper ciphertext: back up the .bin to storage/backup/<id>.bin then flip one byte in the stored file; (2) Tamper metadata: change original_filename in the DB; (3) Replace signature with random bytes; (4) Swap the sender certificate for one issued by a rogue CA (generate a throwaway rogue CA in memory); (5) Restore original (copy back from backup and DB snapshot) so the demo can be repeated. After each attack a link opens the receiver's security-status page showing the red result. Every action is written to activity_log with the label SIMULATED ATTACK.
- "Attacker who steals the data" page: shows exactly what the attacker holds (ciphertext hex preview, wrapped key hex preview, signature, certificate) and a button that tries to decrypt using (a) the attacker's own freshly generated RSA key, (b) a random 256-bit key, (c) the sender's PUBLIC key. All fail; the page explains each failure and the 2^256 brute-force infeasibility (state the arithmetic: even 10^18 guesses per second needs about 3.7 x 10^51 years on average for half the key space) and ends with the concept box: Encrypted File + Encrypted AES Key + No Recipient Private Key -> Attacker cannot recover AES session key -> Original file remains protected.
- scripts/demo_tamper.py (CLI, uses a temp DB and temp CA) printing the exact box for the tampered case (Certificate: VALID, Signature: INVALID, Integrity: FAILED, Status: POSSIBLE TAMPERING); scripts/demo_unauthorized.py covering CASE 1-7 from the brief: invalid login, other user accessing a file (404/403), invalid/expired/untrusted certificate, invalid signature, modified file (GCM tag or signature catches it depending on what was altered), recipient lacking the private key, wrong recipient trying to decrypt; scripts/demo_revocation.py (revoke the sender's certificate -> next verification shows Certificate: INVALID with the reason) and an expiry demo using a certificate issued with a past not_before.
- Admin panel completion (admin_required): users list with enable/disable (is_active), certificate list filtered by status (active/revoked/expired), revoke and, as a bonus, re-issue certificate for a user (requires that user's password, so the admin cannot read private keys), CA information page, recent activity log view with search; none of these pages may ever show private keys, password hashes or encrypted private key blobs.
- tests/test_attacks.py: every lab attack results in a failed verification and refused download; the restore action brings back TRUSTED; DEMO_MODE=0 makes the lab return 404; a non-admin gets 403; disabled users cannot log in; revoked sender certificate blocks download.

Explain with baby steps: for each attack, which defense catches it first and which defense would catch it second (signature vs GCM tag vs certificate check), why tampering with the DB metadata is also caught (it is inside the signed header), and the difference between confidentiality attacks (stolen data) and integrity attacks (modified data).
Test: run each demo script and show expected outputs; run the lab in the browser and record screenshots for the report (list which screenshots to take).
Now start generating Phase 9.
```

## Phase 10 — Hardening, testing, documentation and viva

Goal: security hardening, full test run, README, diagrams, report, presentation, viva answers and the 13-step demo script.

```text
You are a senior applied-cryptography and Flask engineer and a patient mentor. Build PHASE 10 of 10 of the project below. Start generating immediately. Do not ask questions.

=== CIPHERLOCK — PROJECT CONTEXT (identical in every phase) ===
PROJECT: CipherLock — Secure File Storage and Sharing System. College project (Cryptography and Network Security, SPIT Mumbai). A working Flask web prototype that lets one registered user send a file to another so that only the recipient can read it, the recipient can prove who sent it, and any tampering is detected. Real runnable code, not a simulation. Beginner-friendly, modular, heavily commented.

STACK: Python 3.11+, Flask, PyCA "cryptography", sqlite3 (standard library, no ORM), HTML/CSS/JS + Bootstrap 5 (CDN), Werkzeug (password hashing), Flask-WTF (CSRF), python-dotenv, pytest.

SECURITY GOALS: confidentiality (AES-256-GCM), integrity and tamper detection (RSA-PSS signature + GCM tag), sender authentication (X.509 + signature), secure key management (random session keys wrapped with RSA-OAEP), certificate-based trust (mini CA), authorization (only the intended recipient gets the file).

FIXED DESIGN DECISIONS (obey in every phase, never change them):
D1 Hybrid encryption: AES-256-GCM encrypts the file; RSA-OAEP (SHA-256, MGF1-SHA-256) wraps the AES key for the recipient; RSA-PSS (SHA-256, salt length 32) signs. RSA never encrypts the file. ECDSA is never used for encryption. No Base64-as-encryption, no custom algorithms, no hardcoded keys.
D2 Each user has ONE RSA-3072 key pair; X.509 KeyUsage = digitalSignature + keyEncipherment (a simplification; production uses separate signing and encryption keys).
D3 A user's private key is stored only as encrypted PKCS#8 PEM (BestAvailableEncryption, passphrase = the user's password). The password is separately stored as a salted scrypt hash (Werkzeug). The private key is unlocked only inside a single request by asking the user to re-enter the password for signing/decrypting; it is never kept in the session, logged, rendered in HTML or returned by any API.
D4 Mini CA: self-signed Root CA, RSA-4096, 10 years, BasicConstraints CA=true, KeyUsage keyCertSign+cRLSign; CA key stored as encrypted PEM with passphrase from env var CIPHERLOCK_CA_PASSPHRASE (CA operations refuse to run without it). User certificates: 1 year, unique serial, Subject CN=name + emailAddress=email, status active/revoked tracked in DB.
D5 AES-GCM: a new 32-byte key and a new random 12-byte nonce for every shared file; stored ciphertext = ciphertext||16-byte tag (PyCA format); AAD = canonical header bytes.
D6 Canonical signed header (JSON, sorted keys, no spaces, UTF-8): {version, sender_id, receiver_id, original_filename, nonce_b64, wrapped_key_b64, ciphertext_sha256_hex, sender_cert_serial}. Signature = RSA-PSS over these bytes. At verification the ciphertext hash is RECOMPUTED from the stored file (never trusted from the DB).
D7 Receiver pipeline (fail closed): authorization -> certificate check (signed by CipherLock CA, within validity, not revoked, subject email matches sender, key usage OK) -> signature verify -> ONLY THEN unwrap AES key -> AES-GCM decrypt in memory. On failure show: "Signature verification failed. File may have been modified or sender authenticity could not be established." and never decrypt.
D8 Storage: max 25 MB, secure_filename, random stored name <uuid4>.bin in storage/encrypted/, plaintext never written to disk.

MODULE CONTRACT (exact names; later phases rely on them):
crypto/aes.py: generate_session_key()->bytes; encrypt_bytes(key, plaintext, aad)->(nonce, ciphertext_with_tag); decrypt_bytes(key, nonce, data, aad)->bytes
crypto/rsa.py: generate_rsa_keypair(bits=3072); private_key_to_encrypted_pem(priv, passphrase)->bytes; load_private_key(pem, passphrase); public_key_to_pem(pub)->bytes; load_public_key(pem); wrap_session_key(pub, key)->bytes; unwrap_session_key(priv, wrapped)->bytes
crypto/signatures.py: sign_data(priv, data)->bytes; verify_signature(pub, data, sig)->bool
crypto/ca.py: init_ca(); load_ca(); issue_user_certificate(name, email, public_key)->(cert_pem, serial); revoke_certificate(serial)
crypto/certificates.py: load_certificate(pem); verify_certificate(cert_pem, expected_email=None)->CertReport(ca_signature_ok, validity_ok, not_revoked, subject_ok, key_usage_ok, valid, reason)
crypto/package.py: canonical_header(...)->bytes; build_package(...)->dict; verify_package(...)->SecurityReport(certificate, signature, integrity, overall, messages); open_package(...)->bytes
models/user.py and models/file.py: plain sqlite3 helper functions.
DB tables: users(id, name, email UNIQUE, password_hash, public_key, encrypted_private_key, certificate, is_admin, is_active, created_at); files(id, sender_id, receiver_id, original_filename, encrypted_filename, encrypted_session_key, nonce, signature, sender_certificate, ciphertext_sha256, status, created_at); certificates(id, user_id, certificate, serial_number, issued_at, expires_at, status); activity_log(id, user_id, action, detail, created_at).

PROJECT TREE:
CipherLock/ app.py config.py init_db.py requirements.txt .env.example .gitignore README.md
 database/ (cipherlock.db) | routes/ auth.py files.py users.py admin.py | crypto/ aes.py rsa.py signatures.py certificates.py ca.py package.py | models/ user.py file.py | templates/ base.html index.html login.html register.html dashboard.html upload.html sent_files.html received_files.html security_status.html admin.html | static/ css js images | storage/encrypted/ | certificates/ca/ certificates/users/ | keys/ca/ (keys/users/ reserved; user keys live encrypted in the DB) | scripts/ | tests/ | docs/

HOW YOU MUST RESPOND:
1. Begin with a short overview: what this phase builds, why it is needed, how it works, which security principle it demonstrates.
2. List every file to create or modify with its exact path.
3. Give each file as COMPLETE code (no "...", no snippets), with comments explaining every important security or crypto step.
4. Explain in labeled baby steps (Step 1, Step 2, ...) showing all parameters, formulas and substitutions explicitly.
5. Give exact run commands for Windows PowerShell AND macOS/Linux.
6. Give exact test commands and the expected output.
7. Give a table of common errors and fixes.
8. End with a checklist for this phase and tell me what to paste back. Do NOT build later phases.
9. If files from earlier phases are not in this chat, first create minimal compatible versions following the MODULE CONTRACT and PROJECT TREE, marked [STUB — replace with real Phase X file].
=== END CONTEXT ===

PHASE 10 OF 10 — HARDENING, TESTING, DOCUMENTATION AND VIVA
Depends on: Phases 1-9 (the complete working application).

Part A — Hardening (modify existing files, give complete updated files):
- Security headers on every response (after_request): Content-Security-Policy allowing only self and the Bootstrap CDN, X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy no-referrer, Cache-Control no-store on authenticated pages; session cookie Secure flag switchable via .env; simple rate limits on login, upload and download.
- scripts/audit_secrets.py: scans the repo, logs, templates and sample HTTP responses for "PRIVATE KEY", password strings and CA passphrase and fails if any appear outside the encrypted key files; also checks that keys/ and the DB are not tracked by git and that key files have mode 0600 on macOS/Linux.
- Optional local HTTPS: explain flask run with an adhoc or mkcert certificate and explain transport security (TLS) versus application-layer security (CipherLock); say clearly that CipherLock protects stored and shared files, TLS protects the connection.

Part B — Testing:
- scripts/run_all_checks.py running audit_secrets, pytest with coverage, and the CLI demos (e2e_cli, demo_tamper, demo_unauthorized, demo_revocation), printing a single PASS/FAIL summary.
- docs/security_checklist.md: a table mapping each of the 20 security requirements below to the exact file/function that implements it and the test that proves it: never hardcode keys; secure random generation; no plaintext passwords; never expose private keys; no predictable AES keys; never reuse a GCM nonce; RSA-OAEP for wrapping; RSA-PSS for signatures; ECDSA not used for encryption; validate X.509 certificates; check validity period; verify trust chain against the CipherLock CA; verify signatures before treating a file as authentic; never silently decrypt a failed file; validate uploads and filenames; per-user authorization; store encrypted files; protect the CA private key; protect user private keys; no sensitive material in logs.
- docs/test_report.md: test-case table (ID, description, input, expected, actual, PASS/FAIL) covering registration, login, upload, verification, decryption, every tamper case, unauthorized access, revocation, expiry.

Part C — Documentation (complete files):
- README.md: what CipherLock is, features, architecture summary, requirements, step-by-step setup for Windows PowerShell and macOS/Linux (create venv, install requirements, copy .env.example to .env and set SECRET_KEY and CIPHERLOCK_CA_PASSPHRASE, python init_db.py, python scripts/init_ca.py, python scripts/create_admin.py, python app.py, open http://127.0.0.1:5000), how to run tests and demos, project structure, troubleshooting table, limitations.
- docs/architecture.md with Mermaid diagrams: (1) overall architecture (Web App + Mini PKI + crypto layer), (2) registration flow, (3) upload/encrypt/sign flow, (4) receive/verify/decrypt flow with the failure branch, (5) certificate trust chain Root CA -> users, (6) database ER diagram. Also an ASCII version of the main flow for the report.
- docs/report_outline.md: full project-report structure (abstract, introduction, problem statement, objectives, literature/background on AES, RSA, OAEP, PSS, X.509, PKI, system design, implementation per module, testing and results, attack analysis, limitations, future scope, conclusion, references) with 2-3 sentences of ready-to-use text under every heading.
- docs/presentation_outline.md: slide-by-slide outline (about 15 slides) with speaker notes.
- docs/screenshots_checklist.md: the exact screenshots to capture (registration, certificate view, dashboard, upload pipeline, encrypted file in hex view, received list, green security status, red tampered status, unauthorized attempt, admin CA panel, test run, openssl certificate output).
- docs/demo_script.md: a minute-by-minute script for DEMO 1-13 (registration and certificate; login and dashboard; upload; AES-256-GCM encryption; RSA-OAEP protection of the AES key; digital-signature creation; secure sharing; receiver certificate verification; signature verification; session-key recovery; file decryption; tampering attack and failed verification; unauthorized access attempt) with what to click, what to say and what output to point at.
- docs/viva_qa.md: at least 25 model questions and answers, including: why hybrid encryption; why digital signatures; why PKI; what happens if an attacker modifies the file; what happens if the encrypted file is stolen; why GCM instead of CBC; what happens if a GCM nonce is reused; why OAEP and not PKCS#1 v1.5; why PSS; why one key pair per user and what production would do instead; what if the CA private key is stolen; how revocation works here and what CRL/OCSP would add; why re-enter the password to decrypt; why scrypt for passwords; what the AAD does; why the signature covers the ciphertext hash; difference between authentication, integrity and non-repudiation; what TLS adds; limitations (single server, key escrow in DB, no forward secrecy, no key rotation); future work (ECDH + HKDF key agreement, separate signing/encryption keys, HSM or KMS for the CA key, CRL/OCSP, key rotation, multi-recipient sharing by wrapping the AES key once per recipient, chunked streaming encryption for large files).

Explain with baby steps how to run the complete final system from a fresh clone and how to prepare for the live demo (pre-register Siddharth and Vidhi, pre-upload a sample file, keep the lab in DEMO_MODE).
Test: python scripts/run_all_checks.py with the expected final summary.
Now start generating Phase 10.
```

## Final quick-run reference (after all phases)

- Windows PowerShell: python -m venv venv ; venv\\Scripts\\Activate.ps1 ; pip install -r requirements.txt ; copy .env.example .env ; set SECRET\_KEY and CIPHERLOCK\_CA\_PASSPHRASE inside .env ; python init\_db.py ; python scripts/init\_ca.py ; python scripts/create\_admin.py ; python app.py
- macOS/Linux: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && cp .env.example .env && (edit .env) && python init\_db.py && python scripts/init\_ca.py && python scripts/create\_admin.py && python app.py
- Open http://127.0.0.1:5000 in two different browsers (or one normal and one private window) to log in as sender and receiver.
- Run the whole test suite: python scripts/run\_all\_checks.py
- Design choices to mention in the viva: one RSA-3072 key pair per user (simplification), CA key passphrase from an environment variable, private keys encrypted with the user's password and unlocked per request.
