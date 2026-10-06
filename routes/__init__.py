"""
Flask Route Blueprints for PhishGuard Live.
"""
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.scanner import scanner_bp
from routes.api import api_bp
from routes.alerts import alerts_bp
from routes.reports import reports_bp
from routes.admin import admin_bp

__all__ = [
    "auth_bp",
    "dashboard_bp",
    "scanner_bp",
    "api_bp",
    "alerts_bp",
    "reports_bp",
    "admin_bp"
]
