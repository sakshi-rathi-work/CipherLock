"""Create a CipherLock administrator and provision its certificate."""
from __future__ import annotations

import getpass

from app import create_app
from database.db import get_db
from models.provisioning import provision_user_crypto
from models.user import DuplicateEmailError, create_user, hash_password, validate_password


if __name__ == "__main__":
    name = input("Admin full name: ").strip()
    email = input("Admin email: ").strip().lower()
    password = getpass.getpass("Admin password: ")
    errors = validate_password(password)
    if not name or not email or errors:
        raise SystemExit("Invalid admin details: " + " ".join(errors))

    app = create_app()
    with app.app_context():
        db = get_db()
        try:
            user_id = create_user(name, email, hash_password(password), is_admin=True, commit=False)
            provision_user_crypto(user_id, name, email, password)
            db.commit()
        except DuplicateEmailError:
            db.rollback()
            raise SystemExit("An account with this email already exists.")
        except Exception:
            db.rollback()
            raise
    print(f"Admin created successfully with user id {user_id}.")
