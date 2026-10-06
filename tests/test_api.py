"""
RESTful API Endpoint and Telemetry Tests.
"""
from models import ApiLog, Scan

def test_api_health(client):
    """Test /api/health reports connected state."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["application"] == "PhishGuard Live"

def test_api_scan_safe_endpoint(client, app):
    """Test /api/scan with benign URL."""
    payload = {"url": "https://python.org"}
    res = client.post("/api/scan", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["verdict"] == "SAFE"
    assert data["threat_score"] < 30
    assert "scan_id" in data

    # Verify API log entry
    with app.app_context():
        log = ApiLog.query.filter_by(endpoint="/api/scan").first()
        assert log is not None
        assert log.response_status == 200

def test_api_scan_phishing_endpoint(client):
    """Test /api/scan with phishing sample triggers correct alert."""
    payload = {"url": "http://paypal.com.verify-billing-update.xyz/login/secure"}
    res = client.post("/api/scan", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["verdict"] == "PHISHING"
    assert data["threat_score"] >= 60

def test_api_scan_invalid_input(client):
    """Test /api/scan rejects missing or malformed inputs with 400 Bad Request."""
    # Missing payload
    res1 = client.post("/api/scan", json={})
    assert res1.status_code == 400

    # Malformed URL
    res2 = client.post("/api/scan", json={"url": "not-a-valid-domain"})
    assert res2.status_code == 400

def test_api_stats_endpoint(client):
    """Test /api/stats returns aggregated metrics."""
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_scans" in data
    assert "detection_rate_pct" in data

def test_api_scans_and_alerts_endpoints(client):
    """Test /api/scans and /api/alerts feed endpoints."""
    # Seed one scan first
    client.post("/api/scan", json={"url": "https://github.com"})

    res_scans = client.get("/api/scans")
    assert res_scans.status_code == 200
    assert res_scans.get_json()["count"] >= 1

    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    assert "alerts" in res_alerts.get_json()
