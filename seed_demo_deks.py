"""Helper script to seed sample encrypted files with DEKs wrapped under KEK v1.

Use this script before your presentation or video recording to demonstrate:
1. DEKs initially assigned to KEK v1.
2. Rotating to KEK v2.
3. Clicking 'Rewrap All DEKs' to visually watch DEKs migrate from v1 to v2 in real-time.
"""
import secrets
from app import create_app
from database.db import get_db
from models.kms import get_kek_by_version, register_dek
from crypto.kms import generate_dek


def seed_demo_deks(count: int = 5):
    """Reset and force-seed sample files with DEKs wrapped under KEK v1."""
    app = create_app()
    with app.app_context():
        _do_seed(count, force_reset=True)


def seed_demo_deks_if_empty(count: int = 5) -> bool:
    """Seed sample files only if dek_registry has 0 entries (used on server startup)."""
    db = get_db()
    existing = db.execute("SELECT COUNT(*) FROM dek_registry").fetchone()[0]
    if existing > 0:
        return False
    return _do_seed(count, force_reset=False)


def _do_seed(count: int, force_reset: bool = False) -> bool:
    db = get_db()
    kek1, _ = get_kek_by_version(1)

    if force_reset:
        db.execute(
            "DELETE FROM dek_registry WHERE file_id IN (SELECT id FROM files WHERE original_filename LIKE 'demo_doc_%' OR original_filename LIKE 'financial_report_%')"
        )
        db.execute(
            "DELETE FROM files WHERE original_filename LIKE 'demo_doc_%' OR original_filename LIKE 'financial_report_%'"
        )
        db.commit()

    # Get admin sender and receiver user
    user_row = db.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
    sender_id = user_row["id"] if user_row else 1
    second_user = db.execute("SELECT id FROM users WHERE id != ? LIMIT 1", (sender_id,)).fetchone()
    receiver_id = second_user["id"] if second_user else sender_id

    for i in range(1, count + 1):
        filename = f"demo_doc_{i:02d}.pdf"
        enc_name = f"enc_demo_{secrets.token_hex(8)}.bin"
        db.execute(
            """INSERT INTO files (
                sender_id, receiver_id, original_filename, encrypted_filename,
                status, package_version
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (sender_id, receiver_id, filename, enc_name, "active", 1),
        )
        db.commit()
        file_row = db.execute(
            "SELECT id FROM files WHERE encrypted_filename = ?", (enc_name,)
        ).fetchone()
        fid = file_row["id"]
        register_dek(file_id=fid, dek=generate_dek(), kek=kek1, kek_version=1, user_id=sender_id)

    db.commit()
    print(f"[KMS Auto-Seed] Registered {count} sample DEKs under KEK v1 for demonstration.")
    return True


if __name__ == "__main__":
    seed_demo_deks()
