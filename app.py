"""CipherLock application factory and local development entry point."""
import logging
from pathlib import Path

from flask import Flask, jsonify, render_template
from flask_wtf.csrf import CSRFProtect

from config import Config
from database.db import close_db, init_db

csrf = CSRFProtect()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=str((Path(__file__).parent / "instance").resolve()))
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Keep all application-managed directories present, but do not generate
    # certificates or keys here; those belong to later phases.
    for key in ("STORAGE_DIR", "ENCRYPTED_STORAGE_DIR", "CERTIFICATES_DIR",
                "CA_CERTIFICATES_DIR", "USER_CERTIFICATES_DIR", "KEYS_DIR",
                "CA_KEYS_DIR", "USER_KEYS_DIR"):
        Path(app.config[key]).mkdir(parents=True, exist_ok=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    init_db(app.config["DATABASE_PATH"])
    csrf.init_app(app)
    app.teardown_appcontext(close_db)

    from routes.admin import admin_bp
    from routes.auth import auth_bp
    from routes.files import files_bp
    from routes.users import users_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    for blueprint in (files_bp, users_bp, admin_bp):
        app.register_blueprint(blueprint)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/csrf-token")
    def get_csrf_token():
        from flask_wtf.csrf import generate_csrf
        token = generate_csrf()
        response = jsonify({"csrf_token": token})
        response.headers["Cache-Control"] = "no-store"
        return response, 200

    @app.errorhandler(400)
    def bad_request(error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad request"}), 400
        return "Bad Request", 400

    @app.errorhandler(401)
    def unauthorized(error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return "Unauthorized", 401

    @app.errorhandler(403)
    def forbidden(_error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Forbidden"}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Method not allowed"}), 405
        return "Method Not Allowed", 405

    @app.errorhandler(413)
    def too_large(_error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Payload too large"}), 413
        return render_template("errors/413.html"), 413

    @app.errorhandler(429)
    def too_many_requests(_error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "Too many requests"}), 429
        return "Too Many Requests", 429

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        from flask import request
        if request.path.startswith("/api/"):
            return jsonify({"error": "CSRF token missing or invalid"}), 400
        return "Bad Request: CSRF validation failed", 400

    @app.errorhandler(Exception)
    def unexpected_error(error):
        from flask import request
        app.logger.exception("Unhandled application error: %s", error)
        if request.path.startswith("/api/"):
            return jsonify({"error": "An unexpected error occurred."}), 500
        return "An unexpected error occurred.", 500

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="127.0.0.1", port=5000, debug=True)
