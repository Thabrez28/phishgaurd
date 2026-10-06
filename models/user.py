from werkzeug.security import generate_password_hash, check_password_hash
from models import db, utc_now

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)  # "admin" or "user"
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    scans = db.relationship("Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    security_events = db.relationship("SecurityEvent", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        """Hashes password securely using Werkzeug's modern scrypt/pbkdf2."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verifies password hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def record_login_success(self):
        self.failed_login_attempts = 0
        self.last_login = utc_now()


    def record_login_failure(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.is_locked = True

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_locked": self.is_locked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"
