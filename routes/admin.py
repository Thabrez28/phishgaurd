"""
Administrative Operations and SOC Management Routes.
Protected strictly by admin_required decorator.
"""
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User, Scan, Alert, SecurityEvent, ApiLog
from security.security_logger import log_security_event
from routes.auth import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/")
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(15).all()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(15).all()
    security_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(25).all()
    api_logs = ApiLog.query.order_by(ApiLog.created_at.desc()).limit(20).all()
    failed_logins = SecurityEvent.query.filter(SecurityEvent.event_type.in_(["LOGIN_FAILURE", "LOCKED_ACCOUNT_LOGIN_ATTEMPT"])).order_by(SecurityEvent.created_at.desc()).limit(15).all()

    stats = {
        "total_users": User.query.count(),
        "total_scans": Scan.query.count(),
        "total_alerts": Alert.query.count(),
        "total_events": SecurityEvent.query.count(),
        "total_api_calls": ApiLog.query.count()
    }

    return render_template(
        "admin.html",
        users=users,
        scans=recent_scans,
        alerts=recent_alerts,
        security_events=security_events,
        api_logs=api_logs,
        failed_logins=failed_logins,
        stats=stats
    )

@admin_bp.route("/user/<int:user_id>/toggle-lock", methods=["POST"])
@admin_required
def toggle_user_lock(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session.get("user_id"):
        flash("You cannot lock your own administrative account.", "danger")
        return redirect(url_for("admin.admin_panel"))

    user.is_locked = not user.is_locked
    if not user.is_locked:
        user.failed_login_attempts = 0
    db.session.commit()

    action = "locked" if user.is_locked else "unlocked"
    log_security_event(
        event_type="ADMIN_USER_MODIFIED",
        description=f"Admin '{session.get('username')}' {action} account '{user.username}'",
        user_id=session.get("user_id")
    )
    flash(f"User '{user.username}' has been {action}.", "success")
    return redirect(url_for("admin.admin_panel"))

@admin_bp.route("/seed-demo", methods=["POST"])
@admin_required
def seed_demo_data():
    """Seeds synthetic, safe demonstration data without real-world malware."""
    from security.phishing_detector import PhishingDetector

    demo_urls = [
        # Safe examples
        ("https://github.com/explore", "web"),
        ("https://en.wikipedia.org/wiki/Computer_security", "web"),
        ("https://docs.python.org/3/library/urllib.parse.html", "api"),
        ("https://www.render.com/docs/databases", "agent"),
        # Suspicious examples
        ("http://account-update-portal.top/verification?user=demo", "web"),
        ("http://secure-billing-support.xyz/login.php", "api"),
        ("http://192.168.1.100:8080/portal/signin", "agent"),
        # Phishing examples (synthetic, non-malicious domains designed to trigger indicators)
        ("http://paypal.com.verify-billing-update.xyz/login/secure", "web"),
        ("http://login.appleid.apple.com.auth-update.fit/account/confirm", "agent"),
        ("http://security-update-bank@185.190.140.22:8080/signin/wallet/verify", "api")
    ]

    count = 0
    for url, source in demo_urls:
        analysis = PhishingDetector.scan(url)
        if analysis.get("success"):
            scan = Scan(
                user_id=session.get("user_id"),
                url=analysis["url"],
                normalized_url=analysis["normalized_url"],
                threat_score=analysis["threat_score"],
                verdict=analysis["verdict"],
                risk_level=analysis["risk_level"],
                source=source,
                client_ip="127.0.0.1",
                user_agent="PhishGuard-Synthetic-Seeder/1.0"
            )
            scan.set_indicators(analysis["indicators"])
            db.session.add(scan)
            db.session.flush()

            if scan.verdict == "PHISHING":
                alert = Alert(
                    scan_id=scan.id,
                    alert_type="PHISHING URL DETECTED",
                    severity="CRITICAL" if scan.threat_score >= 80 else "HIGH",
                    message=f"[DEMO] Detected synthetic phishing domain: {scan.normalized_url}",
                    status="OPEN"
                )
                db.session.add(alert)
            elif scan.verdict == "SUSPICIOUS":
                alert = Alert(
                    scan_id=scan.id,
                    alert_type="HIGH-RISK URL DETECTED",
                    severity="MEDIUM",
                    message=f"[DEMO] Detected synthetic suspicious structure: {scan.normalized_url}",
                    status="OPEN"
                )
                db.session.add(alert)

            count += 1

    db.session.commit()
    log_security_event(
        event_type="DEMO_DATA_SEEDED",
        description=f"Admin '{session.get('username')}' generated {count} synthetic demonstration records.",
        user_id=session.get("user_id")
    )
    flash(f"Successfully seeded {count} synthetic demonstration records into PostgreSQL database.", "success")
    return redirect(url_for("admin.admin_panel"))
