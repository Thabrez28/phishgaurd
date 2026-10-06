"""
RESTful API Endpoints for PhishGuard Live.
Supports programmatic URL analysis, health checks, external device agents, and telemetry.
"""
from flask import Blueprint, request, jsonify
from sqlalchemy import text
from models import db, Scan, Alert, ApiLog
from security.phishing_detector import PhishingDetector
from security.security_logger import (
    get_client_ip,
    get_client_user_agent,
    log_security_event,
    trigger_security_alert
)

api_bp = Blueprint("api", __name__, url_prefix="/api")

def log_api_call(endpoint: str, method: str, status_code: int):
    """Saves API invocation telemetry to the api_logs table."""
    try:
        log_entry = ApiLog(
            endpoint=endpoint,
            method=method,
            ip_address=get_client_ip(),
            user_agent=get_client_user_agent(),
            response_status=status_code
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[API LOG ERROR] {e}")

@api_bp.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint reporting application and database status.
    Strictly avoids leaking environment secrets.
    """
    db_status = "connected"
    status_code = 200
    try:
        # Check active DB connection with lightweight query
        db.session.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "disconnected"
        status_code = 503

    log_api_call("/api/health", "GET", status_code)
    return jsonify({
        "status": "healthy" if status_code == 200 else "degraded",
        "application": "PhishGuard Live",
        "database": db_status
    }), status_code

@api_bp.route("/scan", methods=["POST"])
def api_scan():
    """
    Performs static URL threat analysis via REST API.
    Used by web clients, automated pipelines, and external CLI agents.
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        # Also check form data for flexibility
        data = request.form

    raw_url = data.get("url")
    if not raw_url or not isinstance(raw_url, str):
        log_api_call("/api/scan", "POST", 400)
        return jsonify({
            "success": False,
            "error": "Missing or invalid 'url' parameter in JSON payload."
        }), 400

    raw_url = raw_url.strip()
    analysis = PhishingDetector.scan(raw_url)

    if not analysis.get("success"):
        log_api_call("/api/scan", "POST", 400)
        return jsonify({
            "success": False,
            "error": analysis.get("error", "URL validation failed.")
        }), 400

    # Save to PostgreSQL
    scan = Scan(
        user_id=None,  # API/agent scan
        url=analysis["url"],
        normalized_url=analysis["normalized_url"],
        threat_score=analysis["threat_score"],
        verdict=analysis["verdict"],
        risk_level=analysis["risk_level"],
        source="api",
        client_ip=get_client_ip(),
        user_agent=get_client_user_agent()
    )
    scan.set_indicators(analysis["indicators"])
    db.session.add(scan)
    db.session.commit()

    # Log security event
    log_security_event(
        event_type="API_SCAN",
        description=f"API scan executed: {scan.verdict} ({scan.threat_score}/100) on {scan.url[:80]}"
    )

    # Trigger alerts for high threats
    if scan.verdict == "PHISHING":
        trigger_security_alert(
            alert_type="PHISHING URL DETECTED",
            severity="CRITICAL" if scan.threat_score >= 80 else "HIGH",
            message=f"Threat detected via API from IP {scan.client_ip}. URL: {scan.normalized_url}. Score: {scan.threat_score}",
            scan_id=scan.id
        )
    elif scan.verdict == "SUSPICIOUS":
        trigger_security_alert(
            alert_type="HIGH-RISK URL DETECTED",
            severity="MEDIUM",
            message=f"Suspicious URL scanned via API from IP {scan.client_ip}. Score: {scan.threat_score}",
            scan_id=scan.id
        )

    log_api_call("/api/scan", "POST", 200)

    return jsonify({
        "success": True,
        "scan_id": scan.id,
        "url": scan.url,
        "normalized_url": scan.normalized_url,
        "threat_score": scan.threat_score,
        "verdict": scan.verdict,
        "risk_level": scan.risk_level,
        "indicators": analysis["indicators"],
        "explanation": analysis["explanation"],
        "recommendation": analysis["recommendation"],
        "scanned_at": scan.created_at.isoformat()
    }), 200

@api_bp.route("/stats", methods=["GET"])
def api_stats():
    """Returns aggregated threat intelligence statistics."""
    total = Scan.query.count()
    safe = Scan.query.filter_by(verdict="SAFE").count()
    suspicious = Scan.query.filter_by(verdict="SUSPICIOUS").count()
    phishing = Scan.query.filter_by(verdict="PHISHING").count()
    active_alerts = Alert.query.filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).count()
    detection_rate = round(((suspicious + phishing) / total * 100), 1) if total > 0 else 0.0

    log_api_call("/api/stats", "GET", 200)

    return jsonify({
        "success": True,
        "total_scans": total,
        "safe_scans": safe,
        "suspicious_scans": suspicious,
        "phishing_scans": phishing,
        "active_alerts": active_alerts,
        "detection_rate_pct": detection_rate
    }), 200

@api_bp.route("/scans", methods=["GET"])
def api_scans():
    """Returns recent scan telemetry."""
    limit = min(request.args.get("limit", 20, type=int), 100)
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(limit).all()
    log_api_call("/api/scans", "GET", 200)
    return jsonify({
        "success": True,
        "count": len(scans),
        "scans": [s.to_dict() for s in scans]
    }), 200

@api_bp.route("/alerts", methods=["GET"])
def api_alerts():
    """Returns list of open and active security alerts."""
    alerts = Alert.query.filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).order_by(Alert.created_at.desc()).limit(50).all()
    log_api_call("/api/alerts", "GET", 200)
    return jsonify({
        "success": True,
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    }), 200
