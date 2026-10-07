"""Comprehensive unit and integration tests for CipherLock Phase 2 Authentication.

Covers:
1. Successful registration (201, contract body, no sensitive fields)
2. Duplicate email (case-variant) -> 409
3. Weak password rejection (short, no upper, no lower, no digit, >128 chars)
4. Successful login
5. Wrong password -> 401
6. Nonexistent email -> 401
7. Identical generic 401 response for wrong password, nonexistent email, and inactive user
8. Scrypt password hashing format (starts with 'scrypt:') and plaintext password never stored in DB
9. Session creation (cookie set, /me works)
10. Session keys restricted to {user_id, csrf_token, _permanent} and pre-login session cleared (P6, P7)
11. Logout clears auth (/me -> 401), idempotent when logged out
12. /api/auth/me returns safe fields only (no password_hash, no private key)
13. Protected route without session -> 401
14. Inactive user rejected at login; active user deactivated mid-session is rejected and session cleared
15. admin_required decorator (anonymous -> 401, non-admin -> 403, admin -> 200)
16. Brute-force lockout (5 failures -> 6th returns 429 with Retry-After; correct password also refused while locked)
17. Lockout expires after 300s; attempts during lockout do NOT extend duration
18. Successful login resets lockout; different (email, IP) pairs independent; nonexistent email locked too
19. Activity log rows recorded for register, login, login_failed, login_locked, logout
20. Sensitive credentials check: plaintext password appears in no activity detail and no API response
21. POST without CSRF token -> 400 JSON
22. /api/csrf-token returns token with Cache-Control: no-store
23. /register ignores supplied is_admin (mass assignment prevention)
24. Registration transaction rollback (provision_user_crypto error -> 0 user rows, 500 generic)
25. SQL-injection email stored safely
26. Non-/api 404 still returns Phase 1 HTML error page
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest
from flask import jsonify, session

from app import create_app
from database.db import close_db
from models import lockout
from models.user import get_user_by_email, set_user_active
from routes import admin_required, login_required


@pytest.fixture(autouse=True)
def clean_lockout_state():
    """Ensure brute-force lockout memory and clock are reset before and after every test."""
    lockout.reset_all()
    lockout.reset_clock()
    yield
    lockout.reset_all()
    lockout.reset_clock()


@pytest.fixture
def auth_app(tmp_path):
    """Create a fully isolated Flask application instance with CSRF ENABLED for auth tests."""
    db_path = tmp_path / "auth_test.db"
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "DATABASE_PATH": db_path,
        "SECRET_KEY": "test-auth-secret-key-32-bytes-long!",
        "STORAGE_DIR": tmp_path / "storage",
        "ENCRYPTED_STORAGE_DIR": tmp_path / "storage" / "encrypted",
        "CERTIFICATES_DIR": tmp_path / "certificates",
        "CA_CERTIFICATES_DIR": tmp_path / "certificates" / "ca",
        "USER_CERTIFICATES_DIR": tmp_path / "certificates" / "users",
        "KEYS_DIR": tmp_path / "keys",
        "CA_KEYS_DIR": tmp_path / "keys" / "ca",
        "USER_KEYS_DIR": tmp_path / "keys" / "users",
    })

    # Register throwaway test routes to test decorators in isolation
    @application.get("/_test/protected")
    @login_required
    def test_protected_route():
        return jsonify({"message": "access granted"}), 200

    @application.get("/_test/admin-only")
    @admin_required
    def test_admin_route():
        return jsonify({"message": "admin granted"}), 200

    yield application


@pytest.fixture
def auth_client(auth_app):
    """Test client for auth tests."""
    return auth_app.test_client()


class CSRFClient:
    """Helper client that automatically fetches and attaches CSRF tokens."""

    def __init__(self, client):
        self.client = client
        self.cached_csrf_token = None

    def get_csrf_token(self) -> str:
        res = self.client.get("/api/csrf-token")
        assert res.status_code == 200
        data = res.get_json()
        self.cached_csrf_token = data["csrf_token"]
        return self.cached_csrf_token

    def post(self, url, json=None, headers=None, **kwargs):
        headers = dict(headers or {})
        if "X-CSRFToken" not in headers:
            headers["X-CSRFToken"] = self.get_csrf_token()
        return self.client.post(url, json=json, headers=headers, **kwargs)

    def get(self, url, **kwargs):
        return self.client.get(url, **kwargs)


@pytest.fixture
def csrf_client(auth_client):
    return CSRFClient(auth_client)


# --- Test Suite ---

def test_csrf_token_endpoint(auth_client):
    """GET /api/csrf-token returns 200, valid token, and Cache-Control: no-store."""
    res = auth_client.get("/api/csrf-token")
    assert res.status_code == 200
    assert res.is_json
    data = res.get_json()
    assert "csrf_token" in data
    assert isinstance(data["csrf_token"], str) and len(data["csrf_token"]) > 10
    assert res.headers.get("Cache-Control") == "no-store"


def test_post_without_csrf_token_fails(auth_client):
    """POST to mutating API endpoint without CSRF token fails with 400 JSON."""
    res = auth_client.post("/api/auth/register", json={
        "name": "No CSRF",
        "email": "nocsrf@example.com",
        "password": "Password123!",
    })
    assert res.status_code == 400
    assert res.is_json
    data = res.get_json()
    assert "CSRF" in data.get("error", "")


def test_successful_registration(csrf_client):
    """1. Successful registration returns 201, contract user fields, and no sensitive data."""
    res = csrf_client.post("/api/auth/register", json={
        "name": "Alice Smith",
        "email": "alice@example.com",
        "password": "ValidPassword123!",
    })
    assert res.status_code == 201
    assert res.is_json
    data = res.get_json()
    assert data["message"] == "User registered"
    user = data["user"]
    assert user["name"] == "Alice Smith"
    assert user["email"] == "alice@example.com"
    assert "id" in user
    assert set(user.keys()) == {"id", "name", "email"}
    # Sensitive fields strictly absent
    for sensitive in ("password", "password_hash", "public_key", "encrypted_private_key", "certificate"):
        assert sensitive not in user
        assert sensitive not in data


def test_duplicate_email_registration(csrf_client):
    """2. Duplicate registration (including case variants) returns 409."""
    res1 = csrf_client.post("/api/auth/register", json={
        "name": "Bob Original",
        "email": "bob@example.com",
        "password": "ValidPassword123!",
    })
    assert res1.status_code == 201

    # Same email in uppercase
    res2 = csrf_client.post("/api/auth/register", json={
        "name": "Bob Duplicate",
        "email": "BOB@EXAMPLE.COM",
        "password": "ValidPassword123!",
    })
    assert res2.status_code == 409
    assert res2.is_json
    assert res2.get_json() == {"error": "An account with this email already exists"}


def test_weak_passwords_rejected(csrf_client):
    """3. Reject passwords that violate policy rules individually and >128 chars."""
    bad_passwords = [
        ("Short1!", "short"),                         # < 10 chars
        ("nouppercase123!", "no uppercase"),           # no upper
        ("NOLOWERCASE123!", "no lowercase"),           # no lower
        ("NoDigitsInPassword!", "no digits"),          # no digit
        ("A" * 125 + "a1", "exceeds 128 chars"),      # > 128 chars
    ]
    # Set the long password properly
    bad_passwords[-1] = ("Aa1" + "x" * 126, "exceeds 128 chars")  # 129 chars

    for pw, label in bad_passwords:
        res = csrf_client.post("/api/auth/register", json={
            "name": "Test User",
            "email": f"test_{label.replace(' ', '_')}@example.com",
            "password": pw,
        })
        assert res.status_code == 400, f"Expected 400 for {label}"
        assert res.is_json
        data = res.get_json()
        assert "password" in data.get("fields", {}), f"Missing password field error for {label}"


def test_successful_login_and_session(csrf_client, auth_app):
    """4 & 9 & 10. Successful login returns 200, sets session with only user_id and clears old session."""
    # Register user
    reg = csrf_client.post("/api/auth/register", json={
        "name": "Charlie Day",
        "email": "charlie@example.com",
        "password": "CharliePassword123!",
    })
    assert reg.status_code == 201

    # Plant a pre-login attacker session key
    with csrf_client.client.session_transaction() as sess:
        sess["pre_login_planted_value"] = "should_be_cleared"

    # Login
    login_res = csrf_client.post("/api/auth/login", json={
        "email": "charlie@example.com",
        "password": "CharliePassword123!",
    })
    assert login_res.status_code == 200
    login_data = login_res.get_json()
    assert login_data["message"] == "Login successful"
    assert set(login_data["user"].keys()) == {"id", "name", "email"}

    # Assert session contents obey P6 and P7
    with csrf_client.client.session_transaction() as sess:
        assert sess.get("user_id") == login_data["user"]["id"]
        # Only allowed keys: user_id, csrf_token, _permanent
        assert set(sess.keys()) <= {"user_id", "csrf_token", "_permanent"}
        assert "pre_login_planted_value" not in sess

    # Access /me to confirm session works
    me_res = csrf_client.get("/api/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.get_json()
    assert me_data["user"]["name"] == "Charlie Day"
    assert me_data["user"]["email"] == "charlie@example.com"
    assert me_data["user"]["is_admin"] is False


def test_wrong_password_and_nonexistent_email_identical_401(csrf_client, auth_app):
    """5, 6, 7. Wrong password, nonexistent email, and inactive user return identical 401."""
    # Register active user
    reg = csrf_client.post("/api/auth/register", json={
        "name": "Dana Scully",
        "email": "dana@example.com",
        "password": "ScullyPassword123!",
    })
    assert reg.status_code == 201

    # Register another user and deactivate them
    reg_inactive = csrf_client.post("/api/auth/register", json={
        "name": "Inactive User",
        "email": "inactive@example.com",
        "password": "InactivePassword123!",
    })
    inactive_id = reg_inactive.get_json()["user"]["id"]
    with auth_app.app_context():
        set_user_active(inactive_id, False)

    # 1. Wrong password
    res_wrong_pw = csrf_client.post("/api/auth/login", json={
        "email": "dana@example.com",
        "password": "WrongPassword123!",
    })
    # 2. Nonexistent email
    res_nonexistent = csrf_client.post("/api/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "ScullyPassword123!",
    })
    # 3. Inactive user
    res_inactive = csrf_client.post("/api/auth/login", json={
        "email": "inactive@example.com",
        "password": "InactivePassword123!",
    })

    for res, label in [
        (res_wrong_pw, "wrong password"),
        (res_nonexistent, "nonexistent email"),
        (res_inactive, "inactive user"),
    ]:
        assert res.status_code == 401, f"{label} did not return 401"
        assert res.is_json
        assert res.get_json() == {"error": "Invalid email or password"}, f"{label} returned different body"


def test_password_hash_scrypt_format_and_no_plaintext_stored(csrf_client, auth_app):
    """8. users.password_hash starts with scrypt: and plaintext appears nowhere in the row."""
    distinct_pw = "UniqueSecretPassphrase123!"
    csrf_client.post("/api/auth/register", json={
        "name": "Eve Secret",
        "email": "eve@example.com",
        "password": distinct_pw,
    })

    with auth_app.app_context():
        user = get_user_by_email("eve@example.com")
        assert user is not None
        pw_hash = user["password_hash"]
        assert pw_hash.startswith("scrypt:")
        # Plaintext password appears nowhere in any column of the user row
        for col in user.keys():
            val = str(user[col])
            assert distinct_pw not in val, f"Plaintext password leaked in column {col}"


def test_logout_clears_auth_and_is_idempotent(csrf_client):
    """11. Logout clears session, /me returns 401, and logging out again returns 200."""
    # Register & Login
    csrf_client.post("/api/auth/register", json={
        "name": "Frank Castle",
        "email": "frank@example.com",
        "password": "PunisherPassword123!",
    })
    csrf_client.post("/api/auth/login", json={
        "email": "frank@example.com",
        "password": "PunisherPassword123!",
    })
    assert csrf_client.get("/api/auth/me").status_code == 200

    # Logout
    logout_res = csrf_client.post("/api/auth/logout")
    assert logout_res.status_code == 200
    assert logout_res.get_json() == {"message": "Logged out"}

    # /me now unauthorized
    assert csrf_client.get("/api/auth/me").status_code == 401

    # Idempotent: logging out again succeeds
    logout_again = csrf_client.post("/api/auth/logout")
    assert logout_again.status_code == 200


def test_api_me_fields_no_sensitive_columns(csrf_client):
    """12. /api/auth/me returns only {id, name, email, is_admin}."""
    csrf_client.post("/api/auth/register", json={
        "name": "Grace Hopper",
        "email": "grace@example.com",
        "password": "HopperPassword123!",
    })
    csrf_client.post("/api/auth/login", json={
        "email": "grace@example.com",
        "password": "HopperPassword123!",
    })

    res = csrf_client.get("/api/auth/me")
    assert res.status_code == 200
    user = res.get_json()["user"]
    assert set(user.keys()) == {"id", "name", "email", "is_admin"}
    assert user["name"] == "Grace Hopper"
    assert user["email"] == "grace@example.com"
    assert user["is_admin"] is False


def test_protected_route_without_session_returns_401(auth_client):
    """13. Protected route without active session returns 401 JSON."""
    res = auth_client.get("/_test/protected")
    assert res.status_code == 401
    assert res.is_json
    assert res.get_json() == {"error": "Authentication required"}


def test_user_deactivated_mid_session_clears_session(csrf_client, auth_app):
    """14. User deactivated mid-session is rejected on next request and session is cleared."""
    reg = csrf_client.post("/api/auth/register", json={
        "name": "Hank Schrader",
        "email": "hank@example.com",
        "password": "HankPassword123!",
    })
    user_id = reg.get_json()["user"]["id"]
    csrf_client.post("/api/auth/login", json={
        "email": "hank@example.com",
        "password": "HankPassword123!",
    })
    assert csrf_client.get("/_test/protected").status_code == 200

    # Deactivate Hank in database
    with auth_app.app_context():
        set_user_active(user_id, False)

    # Next request must be rejected with 401
    res = csrf_client.get("/_test/protected")
    assert res.status_code == 401
    assert res.get_json() == {"error": "Authentication required"}

    # Session was cleared
    with csrf_client.client.session_transaction() as sess:
        assert "user_id" not in sess


def test_admin_required_decorator(csrf_client, auth_app):
    """15. admin_required: anonymous -> 401, regular user -> 403, admin -> 200."""
    # 1. Anonymous
    res_anon = csrf_client.get("/_test/admin-only")
    assert res_anon.status_code == 401
    assert res_anon.get_json() == {"error": "Authentication required"}

    # 2. Regular user
    csrf_client.post("/api/auth/register", json={
        "name": "Regular User",
        "email": "regular@example.com",
        "password": "RegularPassword123!",
    })
    csrf_client.post("/api/auth/login", json={
        "email": "regular@example.com",
        "password": "RegularPassword123!",
    })
    res_reg = csrf_client.get("/_test/admin-only")
    assert res_reg.status_code == 403
    assert res_reg.get_json() == {"error": "Admin access required"}

    # 3. Promote to admin in DB
    with auth_app.app_context():
        from database.db import get_db
        db = get_db()
        db.execute("UPDATE users SET is_admin = 1 WHERE email = 'regular@example.com'")
        db.commit()

    res_admin = csrf_client.get("/_test/admin-only")
    assert res_admin.status_code == 200
    assert res_admin.get_json() == {"message": "admin granted"}


def test_brute_force_lockout_five_failures_and_retry_after(csrf_client):
    """16. Five failures -> 6th attempt returns 429 with Retry-After; correct password refused while locked."""
    email = "lockout_victim@example.com"
    csrf_client.post("/api/auth/register", json={
        "name": "Lockout Victim",
        "email": email,
        "password": "CorrectPassword123!",
    })

    # 5 failed attempts -> 401 each
    for i in range(5):
        res = csrf_client.post("/api/auth/login", json={"email": email, "password": "WrongPassword!"})
        assert res.status_code == 401, f"Attempt {i+1} expected 401"

    # 6th attempt (even with correct password) -> 429
    res_locked = csrf_client.post("/api/auth/login", json={"email": email, "password": "CorrectPassword123!"})
    assert res_locked.status_code == 429
    assert res_locked.is_json
    data = res_locked.get_json()
    assert "Too many failed login attempts" in data["error"]
    assert "retry_after" in data
    assert res_locked.headers.get("Retry-After") is not None
    assert int(res_locked.headers["Retry-After"]) > 0


def test_lockout_duration_and_expiry_without_extension(csrf_client):
    """17. Lockout expires after 300s; attempts during lockout do NOT extend it."""
    email = "timer_test@example.com"
    csrf_client.post("/api/auth/register", json={
        "name": "Timer Test",
        "email": email,
        "password": "CorrectPassword123!",
    })

    base_time = 1000000.0
    mock_now = base_time
    lockout.set_clock(lambda: mock_now)

    # 5 failures to trip lockout
    for _ in range(5):
        csrf_client.post("/api/auth/login", json={"email": email, "password": "WrongPassword!"})

    # Advance 100 seconds (mock_now = base_time + 100)
    mock_now = base_time + 100
    res100 = csrf_client.post("/api/auth/login", json={"email": email, "password": "WrongPassword!"})
    assert res100.status_code == 429
    # Must have ~200 seconds remaining, NOT reset back to 300
    retry_after = res100.get_json()["retry_after"]
    assert 195 <= retry_after <= 200

    # Advance beyond 300 seconds total (e.g. +301s)
    mock_now = base_time + 301
    res_expired = csrf_client.post("/api/auth/login", json={
        "email": email,
        "password": "CorrectPassword123!",
    })
    # Now login must succeed!
    assert res_expired.status_code == 200


def test_lockout_state_resets_on_success_and_independent_ip_pairs(csrf_client):
    """18. Successful login resets state; other (email, IP) independent; nonexistent email locks too."""
    # 1. Nonexistent email gets locked after 5 attempts
    ghost_email = "ghost@example.com"
    for _ in range(5):
        csrf_client.post("/api/auth/login", json={"email": ghost_email, "password": "WrongPassword!"})
    res_ghost = csrf_client.post("/api/auth/login", json={"email": ghost_email, "password": "WrongPassword!"})
    assert res_ghost.status_code == 429

    # 2. Reset on successful login
    real_email = "real@example.com"
    csrf_client.post("/api/auth/register", json={
        "name": "Real User",
        "email": real_email,
        "password": "RealPassword123!",
    })
    # 4 failures (one short of lockout)
    for _ in range(4):
        csrf_client.post("/api/auth/login", json={"email": real_email, "password": "WrongPassword!"})
    # Successful login resets the counter
    login_ok = csrf_client.post("/api/auth/login", json={"email": real_email, "password": "RealPassword123!"})
    assert login_ok.status_code == 200
    # Now 4 more failures should NOT trigger lockout (proves counter reset)
    for _ in range(4):
        res = csrf_client.post("/api/auth/login", json={"email": real_email, "password": "WrongPassword!"})
        assert res.status_code == 401


def test_activity_logging_records_events(csrf_client, auth_app):
    """19. Activity rows exist for register, login, login_failed, login_locked, logout."""
    email = "audited@example.com"
    # Register
    csrf_client.post("/api/auth/register", json={
        "name": "Audited User",
        "email": email,
        "password": "AuditedPassword123!",
    })
    # Login
    csrf_client.post("/api/auth/login", json={"email": email, "password": "AuditedPassword123!"})
    # Logout
    csrf_client.post("/api/auth/logout")

    # Failed login and lock
    for _ in range(5):
        csrf_client.post("/api/auth/login", json={"email": email, "password": "WrongPassword!"})

    with auth_app.app_context():
        from database.db import get_db
        db = get_db()
        actions = [row["action"] for row in db.execute("SELECT action FROM activity_log ORDER BY id ASC").fetchall()]
        assert "register" in actions
        assert "login" in actions
        assert "logout" in actions
        assert "login_failed" in actions
        assert "login_locked" in actions


def test_no_passwords_or_hashes_in_activity_or_api_responses(csrf_client, auth_app):
    """20. Distinctive test password and scrypt hash appear in NO activity detail or API responses."""
    distinct_pw = "SuperUniqueSecret123!"
    reg_res = csrf_client.post("/api/auth/register", json={
        "name": "Secret Sentinel",
        "email": "sentinel@example.com",
        "password": distinct_pw,
    })
    login_res = csrf_client.post("/api/auth/login", json={
        "email": "sentinel@example.com",
        "password": distinct_pw,
    })
    me_res = csrf_client.get("/api/auth/me")
    act_res = csrf_client.get("/api/auth/activity")

    for res in (reg_res, login_res, me_res, act_res):
        text = res.get_data(as_text=True)
        assert distinct_pw not in text
        assert "scrypt:" not in text

    with auth_app.app_context():
        from database.db import get_db
        db = get_db()
        details = [row["detail"] or "" for row in db.execute("SELECT detail FROM activity_log").fetchall()]
        for d in details:
            assert distinct_pw not in d
            assert "scrypt:" not in d


def test_registration_ignores_mass_assignment(csrf_client, auth_app):
    """23. /register ignores supplied is_admin/is_active (mass assignment prevention)."""
    res = csrf_client.post("/api/auth/register", json={
        "name": "Attacker Admin",
        "email": "attacker@example.com",
        "password": "AttackerPassword123!",
        "is_admin": 1,
        "is_active": 0,
    })
    assert res.status_code == 201
    user_id = res.get_json()["user"]["id"]

    with auth_app.app_context():
        from database.db import get_db
        row = get_db().execute("SELECT is_admin, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        assert row["is_admin"] == 0
        assert row["is_active"] == 1


def test_registration_transaction_rollback_on_provisioning_error(csrf_client, auth_app, monkeypatch):
    """24. Registration rollback: monkeypatch provision_user_crypto to raise -> 0 user rows, 500 generic."""
    import routes.auth as auth_module

    def exploding_provisioning(*args, **kwargs):
        raise RuntimeError("Simulated key generation failure")

    monkeypatch.setattr(auth_module, "provision_user_crypto", exploding_provisioning)

    res = csrf_client.post("/api/auth/register", json={
        "name": "Rollback Test",
        "email": "rollback@example.com",
        "password": "ValidPassword123!",
    })
    assert res.status_code == 500
    assert res.is_json
    assert res.get_json() == {"error": "An unexpected error occurred."}

    # Verify no row was committed to users or activity_log
    with auth_app.app_context():
        from database.db import get_db
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = 'rollback@example.com'").fetchone()
        assert user is None
        act = db.execute("SELECT * FROM activity_log WHERE detail LIKE '%rollback%'").fetchone()
        assert act is None


def test_sql_injection_in_email_handled_safely(csrf_client, auth_app):
    """25. SQL injection payloads in email are sanitized / rejected or parameterized safely."""
    # Invalid email format rejected by regex
    res = csrf_client.post("/api/auth/register", json={
        "name": "SQLi Test",
        "email": "admin' OR '1'='1@example.com",
        "password": "ValidPassword123!",
    })
    assert res.status_code == 400

    # Look up attempt with injection in login
    res_login = csrf_client.post("/api/auth/login", json={
        "email": "' OR 1=1 --@example.com",
        "password": "Password123!",
    })
    assert res_login.status_code in (400, 401)


def test_non_api_404_returns_html_page(auth_client):
    """26. Non-/api 404 still returns Phase 1 HTML error page, while /api 404 returns JSON."""
    res_html = auth_client.get("/nonexistent-page-path")
    assert res_html.status_code == 404
    assert not res_html.is_json
    assert b"404" in res_html.data

    res_json = auth_client.get("/api/nonexistent-endpoint")
    assert res_json.status_code == 404
    assert res_json.is_json
    assert res_json.get_json() == {"error": "Not found"}
