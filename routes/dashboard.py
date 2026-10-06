"""
SOC Security Operations Center Dashboard Routes.
Aggregates real-time metrics, threat distributions, and security event timelines directly from PostgreSQL.
"""
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, session
from sqlalchemy import func
from models import db, Scan, Alert, SecurityEvent
from routes.auth import login_required

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    # 1. Total and Verdict Breakdown from DB
    total_scans = db.session.query(func.count(Scan.id)).scalar() or 0
    safe_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "SAFE").scalar() or 0
    suspicious_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "SUSPICIOUS").scalar() or 0
    phishing_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "PHISHING").scalar() or 0

    # 2. Alerts Breakdown
    active_alerts = db.session.query(func.count(Alert.id)).filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).scalar() or 0
    critical_alerts = db.session.query(func.count(Alert.id)).filter(
        Alert.status.in_(["OPEN", "INVESTIGATING"]),
        Alert.severity == "CRITICAL"
    ).scalar() or 0

    # 3. Severity Distribution
    severity_counts = {
        "LOW": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "LOW").scalar() or 0,
        "MEDIUM": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "MEDIUM").scalar() or 0,
        "HIGH": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "HIGH").scalar() or 0,
        "CRITICAL": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "CRITICAL").scalar() or 0
    }

    # 4. Activity Over Last 7 Days
    from models import utc_now
    current_utc = utc_now()
    seven_days_ago = current_utc - timedelta(days=7)
    recent_scans_by_day = (
        db.session.query(func.date(Scan.created_at).label("scan_date"), func.count(Scan.id).label("count"))
        .filter(Scan.created_at >= seven_days_ago)
        .group_by(func.date(Scan.created_at))
        .order_by(func.date(Scan.created_at).asc())
        .all()
    )

    # Convert to chart labels and series
    dates = []
    daily_counts = []
    # Fill standard 7 day window
    for i in range(6, -1, -1):
        target_day = current_utc - timedelta(days=i)
        day_str = target_day.strftime("%Y-%m-%d")
        dates.append(target_day.strftime("%b %d"))
        match = next((item.count for item in recent_scans_by_day if str(item.scan_date) == day_str), 0)
        daily_counts.append(match)


    # 5. Recent Scans & Events
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(8).all()
    recent_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(8).all()
    recent_alerts = Alert.query.filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).order_by(Alert.created_at.desc()).limit(5).all()

    # Detection rate calculation
    threat_total = suspicious_scans + phishing_scans
    detection_rate = round((threat_total / total_scans * 100), 1) if total_scans > 0 else 0.0

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        phishing_scans=phishing_scans,
        active_alerts=active_alerts,
        critical_alerts=critical_alerts,
        detection_rate=detection_rate,
        severity_counts=severity_counts,
        dates=dates,
        daily_counts=daily_counts,
        recent_scans=recent_scans,
        recent_events=recent_events,
        recent_alerts=recent_alerts
    )

@dashboard_bp.route("/api-docs")
def api_docs():
    """Renders comprehensive in-app REST API documentation with live examples."""
    return render_template("api_docs.html")

@dashboard_bp.route("/external-device")
def external_device():
    """External device connectivity guide and live telemetry inspection."""
    from security.security_logger import get_client_ip, get_client_user_agent
    client_ip = get_client_ip()
    user_agent = get_client_user_agent()
    return render_template(
        "external_device.html",
        client_ip=client_ip,
        user_agent=user_agent
    )

