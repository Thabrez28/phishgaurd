"""
PhishGuard Live - Database Models
PostgreSQL database models for users, scans, alerts,
security events, and API telemetry.
"""

import json
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="user")

    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)

    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    scans = db.relationship(
        "Scan",
        backref="user",
        lazy=True
    )

    security_events = db.relationship(
        "SecurityEvent",
        backref="user",
        lazy=True
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def record_login_success(self):
        self.failed_login_attempts = 0
        self.is_locked = False
        self.last_login = datetime.utcnow()

    def record_login_failure(self):
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.is_locked = True

    def __repr__(self):
        return f"<User {self.username}>"


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    url = db.Column(db.Text, nullable=False)
    normalized_url = db.Column(db.Text, nullable=False)

    threat_score = db.Column(db.Integer, nullable=False, default=0)

    verdict = db.Column(
        db.String(20),
        nullable=False,
        index=True
    )

    risk_level = db.Column(
        db.String(20),
        nullable=False,
        index=True
    )

    source = db.Column(
        db.String(30),
        nullable=False,
        default="web"
    )

    client_ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    indicators = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    alerts = db.relationship(
        "Alert",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def set_indicators(self, indicators):
        """
        Store URL threat indicators as JSON.
        """
        try:
            self.indicators = json.dumps(indicators or [])
        except (TypeError, ValueError):
            self.indicators = json.dumps([])

    def get_indicators(self):
        """
        Return stored URL threat indicators.
        """
        if not self.indicators:
            return []

        try:
            return json.loads(self.indicators)
        except (TypeError, ValueError, json.JSONDecodeError):
            return []

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "threat_score": self.threat_score,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "source": self.source,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "indicators": self.get_indicators(),
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }

    def __repr__(self):
        return f"<Scan {self.id} {self.verdict}>"


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=True
    )

    alert_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="MEDIUM",
        index=True
    )

    message = db.Column(db.Text, nullable=False)

    status = db.Column(
        db.String(20),
        nullable=False,
        default="OPEN",
        index=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(100), nullable=True)

    def resolve(self, username):
        self.status = "RESOLVED"
        self.resolved_at = datetime.utcnow()
        self.resolved_by = username

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "status": self.status,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "resolved_at": (
                self.resolved_at.isoformat()
                if self.resolved_at
                else None
            ),
            "resolved_by": self.resolved_by
        }

    def __repr__(self):
        return f"<Alert {self.id} {self.severity}>"


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    event_type = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    description = db.Column(db.Text, nullable=False)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "description": self.description,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }

    def __repr__(self):
        return f"<SecurityEvent {self.event_type}>"


class ApiLog(db.Model):
    __tablename__ = "api_logs"

    id = db.Column(db.Integer, primary_key=True)

    endpoint = db.Column(
        db.String(255),
        nullable=False
    )

    method = db.Column(
        db.String(10),
        nullable=False
    )

    ip_address = db.Column(
        db.String(64),
        nullable=True
    )

    user_agent = db.Column(
        db.Text,
        nullable=True
    )

    response_status = db.Column(
        db.Integer,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    def to_dict(self):
        return {
            "id": self.id,
            "endpoint": self.endpoint,
            "method": self.method,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "response_status": self.response_status,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }

    def __repr__(self):
        return f"<ApiLog {self.method} {self.endpoint}>"