"""
Security Auditing, Logging, and Automated Alert Dispatcher.
"""
from flask import request
from models import db
from models.security_event import SecurityEvent
from models.alert import Alert

def get_client_ip() -> str:
    """
    Safely retrieves the real client IP address, accounting for Render's reverse proxy headers.
    """
    if not request:
        return "127.0.0.1"
    
    # Render and standard reverse proxies populate X-Forwarded-For
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the leftmost untrusted client IP
        return forwarded_for.split(",")[0].strip()
    
    return request.remote_addr or "127.0.0.1"

def get_client_user_agent() -> str:
    """Retrieves client user agent string truncated to fit database schema."""
    if not request or not request.user_agent:
        return "Unknown"
    return str(request.user_agent)[:250]

def log_security_event(event_type: str, description: str, user_id=None, ip_address=None, user_agent=None) -> SecurityEvent:
    """
    Persists a security audit event to the database.
    """
    try:
        ip = ip_address or get_client_ip()
        ua = user_agent or get_client_user_agent()
        
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip,
            user_agent=ua,
            description=description
        )
        db.session.add(event)
        db.session.commit()
        return event
    except Exception as e:
        db.session.rollback()
        # Fallback print if DB commit fails
        print(f"[SECURITY EVENT LOGGING ERROR] {e}")
        return None

def trigger_security_alert(alert_type: str, severity: str, message: str, scan_id=None) -> Alert:
    """
    Automatically creates a high-priority SOC security alert.
    """
    try:
        alert = Alert(
            scan_id=scan_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            status="OPEN"
        )
        db.session.add(alert)
        db.session.commit()
        return alert
    except Exception as e:
        db.session.rollback()
        print(f"[SECURITY ALERT CREATION ERROR] {e}")
        return None
