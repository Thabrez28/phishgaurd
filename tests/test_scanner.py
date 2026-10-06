"""
URL Threat Scanner and Static Heuristics Engine Tests.
"""
from security.phishing_detector import PhishingDetector
from security.url_analyzer import calculate_shannon_entropy, extract_features

def test_url_validation():
    """Verify input validation rejects malformed and unsafe protocols."""
    valid, _ = PhishingDetector.validate_url("https://example.com/login")
    assert valid is True

    # Reject dangerous protocols
    valid_file, err_file = PhishingDetector.validate_url("file:///etc/passwd")
    assert valid_file is False
    assert "dangerous URI scheme" in err_file

    valid_js, err_js = PhishingDetector.validate_url("javascript:alert(1)")
    assert valid_js is False

    # Reject empty
    valid_empty, _ = PhishingDetector.validate_url("")
    assert valid_empty is False

def test_shannon_entropy():
    """Verify entropy algorithm detects high randomness."""
    low_entropy = calculate_shannon_entropy("google.com")
    high_entropy = calculate_shannon_entropy("x8q9z3w71jklmqrstvx89.xyz")
    
    assert low_entropy < 3.2
    assert high_entropy > 3.8

def test_safe_url_scan():
    """Legitimate standard URLs must yield SAFE verdict and score < 30."""
    result = PhishingDetector.scan("https://docs.python.org/3/library/urllib.parse.html")
    assert result["success"] is True
    assert result["verdict"] == "SAFE"
    assert result["risk_level"] == "LOW"
    assert result["threat_score"] < 30

def test_suspicious_url_scan():
    """Anomalous structural patterns must yield SUSPICIOUS verdict."""
    result = PhishingDetector.scan("http://account-update-portal.top/verification?user=demo")
    assert result["success"] is True
    assert result["verdict"] in ["SUSPICIOUS", "PHISHING"]
    assert result["threat_score"] >= 30

def test_phishing_url_scan():
    """Brand spoofing and abused TLDs must trigger PHISHING verdict and score >= 60."""
    result = PhishingDetector.scan("http://paypal.com.verify-billing-update.xyz/login/secure")
    assert result["success"] is True
    assert result["verdict"] == "PHISHING"
    assert result["threat_score"] >= 60
    assert any("Brand Impersonation" in ind["name"] for ind in result["indicators"])

def test_deterministic_scoring():
    """Engine must be strictly deterministic (re-running produces identical score)."""
    target = "http://login.appleid.apple.com.auth-update.fit/account/confirm"
    res1 = PhishingDetector.scan(target)
    res2 = PhishingDetector.scan(target)
    res3 = PhishingDetector.scan(target)

    assert res1["threat_score"] == res2["threat_score"] == res3["threat_score"]
    assert res1["verdict"] == res2["verdict"] == res3["verdict"]

def test_scanner_web_workflow(client, test_user):
    """Test authenticated scanning through Flask web view."""
    client.post("/login", data={
        "username": "analyst1",
        "password": "SecurePass123!"
    })

    res = client.post("/scanner", data={
        "url": "https://en.wikipedia.org/wiki/Phishing"
    })
    assert res.status_code == 200
    assert b"VERDICT: SAFE" in res.data
