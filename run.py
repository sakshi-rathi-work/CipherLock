"""CipherLock development server entrypoint."""
import logging
from app import create_app

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
