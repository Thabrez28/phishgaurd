from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def utc_now():
    """Returns timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


from models.user import User
from models.scan import Scan
from models.alert import Alert
from models.security_event import SecurityEvent
from models.api_log import ApiLog

__all__ = ["db", "User", "Scan", "Alert", "SecurityEvent", "ApiLog"]
