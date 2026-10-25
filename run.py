"""CipherLock development server entrypoint."""
import logging
from app import create_app

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    with app.app_context():
        try:
            from seed_demo_deks import seed_demo_deks_if_empty
            seed_demo_deks_if_empty()
        except Exception as exc:
            logging.debug("KMS demo auto-seeding skipped: %s", exc)
    app.run(host="127.0.0.1", port=5000, debug=True)
