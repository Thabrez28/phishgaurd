"""
PhishGuard Live - Autonomous Cybersecurity Web Platform.
Main Flask application entry point and factory.
"""
import os
from flask import Flask, render_template, jsonify, request
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config_by_name
from models import db, User, Alert
from routes import (
    auth_bp,
    dashboard_bp,
    scanner_bp,
    api_bp,
    alerts_bp,
    reports_bp,
    admin_bp
)

migrate = Migrate()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour", "40 per minute"]
)

def create_app(config_name=None):
    """Application factory for PhishGuard Live."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")
        if config_name not in config_by_name:
            config_name = "default"

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)

    # Exclude static assets from rate limiter
    limiter.exempt(dashboard_bp)

    # Context processors for templates
    @app.context_processor
    def inject_global_vars():
        active_alert_count = 0
        try:
            active_alert_count = Alert.query.filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).count()
        except Exception:
            pass

        return {
            "app_name": "PhishGuard Live",
            "app_subtitle": "Cloud Cybersecurity & Threat Monitoring",
            "version": "v5.2.0-PROD",
            "active_alert_count": active_alert_count
        }

    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        headers = app.config.get("SECURITY_HEADERS", {})
        for header, val in headers.items():
            response.headers[header] = val
        return response

    # Global HTTP error handlers
    @app.errorhandler(403)
    def forbidden(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Access forbidden: Insufficient privileges"}), 403
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Resource not found"}), 404
        return render_template("404.html"), 404

    @app.errorhandler(429)
    def ratelimit_handler(error):
        from security.security_logger import trigger_security_alert, log_security_event
        try:
            log_security_event("RATE_LIMIT_TRIGGERED", f"Rate limit exceeded on '{request.path}'")
            trigger_security_alert(
                alert_type="RATE LIMIT TRIGGERED",
                severity="MEDIUM",
                message=f"Rate limit exceeded on endpoint '{request.path}' from IP: {request.remote_addr}"
            )
        except Exception:
            pass

        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Rate limit exceeded. Please throttle requests."}), 429
        return render_template("429.html"), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Internal cybersecurity system error"}), 500
        return render_template("500.html"), 500

    # Auto-initialize database tables and default admin if not created
    with app.app_context():
        try:
            db.create_all()
            # Seed default admin if user table empty
            if User.query.count() == 0:
                admin_user = User(
                    username=app.config.get("ADMIN_USERNAME", "admin"),
                    email=app.config.get("ADMIN_EMAIL", "admin@phishguard.live"),
                    role="admin"
                )
                admin_user.set_password(app.config.get("ADMIN_PASSWORD", "Admin@PhishGuard2026!"))
                db.session.add(admin_user)
                db.session.commit()
                print(f"[BOOTSTRAP] Created default administrative user '{admin_user.username}'")
        except Exception as e:
            print(f"[BOOTSTRAP NOTICE] Database setup warning: {e}")

    return app

# Gunicorn entry point
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
