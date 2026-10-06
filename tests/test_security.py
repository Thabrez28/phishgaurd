"""
Cybersecurity Defenses, Security Headers, and Exception Resilience Tests.
"""
from models import SecurityEvent

def test_security_headers_present(client):
    """Verify defensive HTTP security headers are injected into every response."""
    res = client.get("/login")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in res.headers
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

def test_custom_404_handler(client):
    """Custom 404 page must be rendered without server crash or stack traces."""
    res = client.get("/non-existent-endpoint-test")
    assert res.status_code == 404
    assert b"404 TARGET NOT FOUND" in res.data

def test_sql_injection_resilience(client):
    """Verify ORM parametrization protects against classic SQL injection attempts."""
    # Attempt SQL injection in login
    injection_payload = "' OR 1=1; DROP TABLE users; --"
    res = client.post("/login", data={
        "username": injection_payload,
        "password": "random_password"
    })
    # Should cleanly reject login without database error
    assert res.status_code == 200
    assert b"Invalid credentials" in res.data

def test_security_event_logging(app):
    """Verify security logger writes events without crashing."""
    from security.security_logger import log_security_event
    from models import db
    with app.app_context():
        event = log_security_event("TEST_EVENT", "Security unit test event execution")
        assert event is not None
        assert event.id is not None
        saved = db.session.get(SecurityEvent, event.id)
        assert saved.event_type == "TEST_EVENT"
