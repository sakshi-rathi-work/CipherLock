"""CipherLock application factory and local development entry point."""
import io
import logging
from pathlib import Path

from flask import Flask, Request, jsonify, render_template
from flask_wtf.csrf import CSRFProtect

from config import Config
from database.db import close_db, init_db

csrf = CSRFProtect()


class InMemoryUploadRequest(Request):
    """Keep multipart file parts in memory instead of spooling them to /tmp.

    Werkzeug's default stream factory writes uploads larger than ~500 KB to a
    temporary file. CipherLock must never persist plaintext, so uploaded file
    parts are buffered in ``BytesIO`` (bounded by ``MAX_CONTENT_LENGTH``) and
    encrypted before anything reaches the filesystem.
    """

    def _get_file_stream(self, total_content_length, content_type, filename=None,
                         content_length=None):
        return io.BytesIO()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=str((Path(__file__).parent / "instance").resolve()))
    app.request_class = InMemoryUploadRequest
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
    from routes.files import files_bp, files_web_bp
    from routes.kms import kms_bp
    from routes.users import users_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(files_web_bp)
    for blueprint in (files_bp, users_bp, admin_bp, kms_bp):
        app.register_blueprint(blueprint)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/dashboard")
    def dashboard():
        from flask import redirect, session
        user_id = session.get("user_id")
        if not user_id:
            frontend_url = app.config.get("FRONTEND_URL")
            return redirect(f"{frontend_url}/login" if frontend_url else "/login")
        from models.user import get_user_by_id
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            return redirect("/login")
        from models.file import list_received, count_sent, count_received, file_to_dict
        from models.activity import list_recent_activity
        received_rows, received_total = list_received(user_id, limit=10)
        received_files = [file_to_dict(r) for r in received_rows]
        activity = list_recent_activity(user_id, limit=10)
        return render_template(
            "dashboard.html",
            user=user,
            received_files=received_files,
            sent_count=count_sent(user_id),
            received_count=received_total,
            activity=activity,
        )

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

    @app.route("/login", methods=["GET", "POST"])
    def login():
        from flask import flash, redirect, render_template, request, session, url_for
        if session.get("user_id"):
            return redirect(request.args.get("next") or "/admin/kms")
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            from models.user import get_user_by_email, verify_password
            user = get_user_by_email(email)
            if user and verify_password(user["password_hash"], password) and user["is_active"]:
                session.clear()
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                next_url = request.args.get("next") or ("/admin/kms" if user["is_admin"] else "/dashboard")
                return redirect(next_url)
            flash("Invalid email or password", "error")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        from flask import redirect, session
        session.clear()
        return redirect("/login")

    @app.get("/admin/kms")
    def kms_dashboard():
        from flask import redirect, request, session as flask_session, url_for
        user_id = flask_session.get("user_id")
        if not user_id:
            return redirect(url_for("login", next=request.path))
        from models.user import get_user_by_id
        user = get_user_by_id(user_id)
        if not user:
            flask_session.clear()
            return redirect(url_for("login", next=request.path))
        if not user["is_admin"]:
            from flask import abort
            abort(403)
        return render_template("kms_dashboard.html", user=user)

    # Bootstrap KMS schema and initial KEK on first start.
    with app.app_context():
        try:
            from models.kms import ensure_kms_initialized
            ensure_kms_initialized()
        except Exception:
            app.logger.warning("KMS auto-initialization deferred (DB may not be ready)")


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
