# Contributing to CipherLock

Thank you for taking the time to read this guide.  CipherLock is a college
**Computer Network Security** project built in phases, so most contributions
involve extending a completed phase or filling in placeholder modules
for the next one.

---

## Table of Contents

1. [Getting the project running](#1-getting-the-project-running)
2. [Project layout at a glance](#2-project-layout-at-a-glance)
3. [Branch and commit conventions](#3-branch-and-commit-conventions)
4. [Coding conventions](#4-coding-conventions)
5. [Running the test suite](#5-running-the-test-suite)
6. [Security rules](#6-security-rules)
7. [Submitting a pull request](#7-submitting-a-pull-request)

---

## 1. Getting the project running

### Prerequisites

- Python 3.11 or newer
- Git

### Setup (Windows PowerShell)

```powershell
# 1. Clone (or fork + clone) the repository
git clone https://github.com/sakshi-rathi-work/CipherLock.git
cd CipherLock

# 2. Create and activate a virtual environment
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install -r requirements.txt

# 4. Copy the example environment file and review the settings
Copy-Item .env.example .env

# 5. Verify your environment
python scripts/check_env.py

# 6. Initialise the database
python init_db.py

# 7. Start the development server
python app.py
```

The landing page is served at <http://127.0.0.1:5000/>.
The health endpoint is at <http://127.0.0.1:5000/health>.

### Setup (macOS / Linux)

```bash
git clone https://github.com/sakshi-rathi-work/CipherLock.git
cd CipherLock
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python scripts/check_env.py
python init_db.py
python app.py
```

---

## 2. Project layout at a glance

```
app.py              Application factory and dev entry point
config.py           All configuration, loaded from environment
init_db.py          One-shot database initialisation command
conftest.py         Shared pytest fixtures
pytest.ini          Test discovery and output settings

database/
  schema.sql        Versioned SQLite schema (idempotent)
  db.py             Connection lifecycle helpers

routes/             One Blueprint per area (auth, files, users, admin)
models/             Reserved – future SQLite row helpers
crypto/             Reserved – future AES-GCM / RSA / X.509 modules
templates/          Jinja2 HTML (base layout, pages, error pages)
static/css/         Core styles (style.css) + animation layer (landing.css)
static/js/          Landing interactions (main.js)
static/images/      Reserved – future UI images
scripts/            Developer utilities (check_env.py)
tests/              pytest test modules
docs/               Architecture and design documentation
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a detailed breakdown.

---

## 3. Branch and commit conventions

### Branches

| Branch pattern | Purpose |
|---|---|
| `main` | Stable, reviewed code only |
| `feat/<short-description>` | New feature or module |
| `fix/<short-description>` | Bug fix |
| `docs/<short-description>` | Documentation only |
| `test/<short-description>` | Tests only |
| `chore/<short-description>` | Tooling, config, build |

### Commit messages

Follow the **Conventional Commits** format:

```
<type>(<optional scope>): <short summary in present tense>

<optional body – explain WHY, not just WHAT>
```

**Types:** `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`, `style`

**Examples:**

```
feat(auth): add user registration route and form validation

fix(db): ensure foreign_keys pragma is set before schema migration

docs: update ARCHITECTURE.md to cover Phase 2 session management

test(auth): add parametrized tests for invalid login attempts
```

- Keep the subject line under 72 characters.
- Use the body to explain *why* the change is needed, not just what it does.
- Reference issue numbers in the footer if applicable: `Closes #12`.

---

## 4. Coding conventions

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use **type hints** for all public function signatures.
- Write **docstrings** for every module, class, and public function.
- Prefer `pathlib.Path` over `os.path` for file operations.
- Do not print secrets, tokens, or key material anywhere in application code.

### SQL

- Keep all schema changes in `database/schema.sql` using `IF NOT EXISTS`
  guards so the file remains idempotent.
- Document the purpose of every column with a comment when the name is not
  self-explanatory.

### HTML / CSS / JS

- All markup goes through Jinja2 templates; no inline HTML in Python strings.
- CSS design tokens (colours, spacing) live in the `:root` block in
  `static/css/style.css`.
- Animation and interaction styles live in `static/css/landing.css`.
- JavaScript in `static/js/main.js` must work without a build step (plain
  ES2020, no bundler required).  Use `defer` when loading scripts.

---

## 5. Running the test suite

```bash
# Run all tests with short output
python -m pytest -q

# Run a single file
python -m pytest tests/test_app.py -v

# Run with coverage (install pytest-cov first)
python -m pip install pytest-cov
python -m pytest --cov=. --cov-report=term-missing
```

`pytest.ini` configures test discovery and warning filters automatically.
The `conftest.py` at the project root provides shared fixtures; individual
test modules may define additional local fixtures.

All new features should include tests.  Aim to keep the test suite green
before opening a pull request.

---

## 6. Security rules

These rules are **non-negotiable** and apply to every contribution:

1. **Never commit secrets.**  `.env` is git-ignored; keep it that way.
   Use `.env.example` for placeholder documentation.
2. **Never commit generated runtime files.**  This includes `database/*.db`,
   `instance/*`, `storage/*`, private keys, and certificate files.
3. **Check `.gitignore` before staging.**  Run `git status` and review
   the diff carefully, especially after adding new file paths.
4. **Do not print secrets.**  `scripts/check_env.py` demonstrates the
   correct pattern: print *whether* a value is set, not the value itself.
5. **Cryptographic operations belong in `crypto/`.**  No raw `hashlib`,
   `secrets`, or `cryptography` calls should appear in route handlers;
   delegate to helpers in the `crypto/` module.

---

## 7. Submitting a pull request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes and write or update tests as needed.
3. Ensure `python -m pytest -q` passes with no failures.
4. Run `python scripts/check_env.py` to confirm nothing is misconfigured.
5. Push your branch and open a pull request against `main`.
6. Fill in the pull request description: what changed, why, and how to
   test it.

Pull requests that add secrets, committed databases, private keys, or
generated runtime files will be closed without review.
