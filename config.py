"""
PhishGuard Live - Configuration Module
Supports both Cloud Production (Render + PostgreSQL) and Local Development (SQLite).
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load local environment variables from .env if present
load_dotenv()

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishguard-dev-supersecret-key-32chars-min-soc")
    
    # Database URL adaptation for PostgreSQL & Render
    _raw_db_url = os.environ.get("DATABASE_URL")
    if _raw_db_url:
        # SQLAlchemy 1.4+ / 2.0+ requires postgresql:// instead of postgres://
        if _raw_db_url.startswith("postgres://"):
            SQLALCHEMY_DATABASE_URI = _raw_db_url.replace("postgres://", "postgresql://", 1)
        else:
            SQLALCHEMY_DATABASE_URI = _raw_db_url
    else:
        # Local development fallback
        SQLALCHEMY_DATABASE_URI = "sqlite:///phishguard.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    } if not SQLALCHEMY_DATABASE_URI.startswith("sqlite") else {}

    # Session & Security Cookie Settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    
    # In production or on Render, enforce HTTPS cookies
    IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production" or os.environ.get("RENDER") is not None
    SESSION_COOKIE_SECURE = IS_PRODUCTION

    # Rate Limiter
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200/hour;30/minute")
    RATELIMIT_STRATEGY = "fixed-window"

    # Security Headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
        )
    }

    # Admin Defaults for Initial DB Seed
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@phishguard.live")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@PhishGuard2026!")

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False

config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig if os.environ.get("FLASK_ENV") != "production" else ProductionConfig
}
