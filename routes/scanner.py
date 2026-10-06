"""
URL Threat Scanner and Analysis Routes.
Executes static URL inspection, stores results to PostgreSQL, and triggers automated security alerts.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, Scan
from security.phishing_detector import PhishingDetector
from security.security_logger import (
    log_security_event,
    trigger_security_alert,
    get_client_ip,
    get_client_user_agent
)
from routes.auth import login_required

scanner_bp = Blueprint("scanner", __name__)

@scanner_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    result = None
    target_url = ""

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()
        user_id = session.get("user_id")

        if not target_url:
            flash("Please enter a target URL to analyze.", "warning")
            return render_template("scanner.html", target_url=target_url)

        # Run static detection engine
        analysis = PhishingDetector.scan(target_url)

        if not analysis.get("success"):
            flash(analysis.get("error", "Invalid URL provided."), "danger")
            return render_template("scanner.html", target_url=target_url)

        # Persist to database
        scan = Scan(
            user_id=user_id,
            url=analysis["url"],
            normalized_url=analysis["normalized_url"],
            threat_score=analysis["threat_score"],
            verdict=analysis["verdict"],
            risk_level=analysis["risk_level"],
            source="web",
            client_ip=get_client_ip(),
            user_agent=get_client_user_agent()
        )
        scan.set_indicators(analysis["indicators"])
        db.session.add(scan)
        db.session.commit()

        # Security auditing & automated alerts
        if scan.verdict == "PHISHING":
            log_security_event(
                event_type="PHISHING_DETECTED",
                description=f"Phishing URL identified (Score: {scan.threat_score}/100): {scan.url[:80]}",
                user_id=user_id
            )
            trigger_security_alert(
                alert_type="PHISHING URL DETECTED",
                severity="CRITICAL" if scan.threat_score >= 80 else "HIGH",
                message=f"Threat engine confirmed phishing indicators on domain '{scan.normalized_url}'. Threat Score: {scan.threat_score}.",
                scan_id=scan.id
            )
        elif scan.verdict == "SUSPICIOUS":
            log_security_event(
                event_type="SUSPICIOUS_DETECTED",
                description=f"Suspicious URL identified (Score: {scan.threat_score}/100): {scan.url[:80]}",
                user_id=user_id
            )
            trigger_security_alert(
                alert_type="HIGH-RISK URL DETECTED",
                severity="HIGH" if scan.risk_level == "HIGH" else "MEDIUM",
                message=f"Suspicious URL scanned with {len(analysis['indicators'])} risk anomalies. Score: {scan.threat_score}.",
                scan_id=scan.id
            )
        else:
            log_security_event(
                event_type="URL_SCAN",
                description=f"Safe URL scanned (Score: {scan.threat_score}/100): {scan.url[:80]}",
                user_id=user_id
            )

        result = {
            "id": scan.id,
            "url": scan.url,
            "normalized_url": scan.normalized_url,
            "threat_score": scan.threat_score,
            "verdict": scan.verdict,
            "risk_level": scan.risk_level,
            "indicators": analysis["indicators"],
            "features": analysis["features"],
            "explanation": analysis["explanation"],
            "recommendation": analysis["recommendation"],
            "created_at": scan.created_at
        }

    return render_template("scanner.html", result=result, target_url=target_url)

@scanner_bp.route("/result/<int:scan_id>")
@login_required
def result_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    # Re-extract features for detailed technical breakdown display
    features = PhishingDetector.scan(scan.url).get("features", {})
    return render_template("result.html", scan=scan, indicators=scan.get_indicators(), features=features)

@scanner_bp.route("/history")
@login_required
def history():
    verdict_filter = request.args.get("verdict", "").strip().upper()
    search_query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)

    query = Scan.query

    if verdict_filter in ["SAFE", "SUSPICIOUS", "PHISHING"]:
        query = query.filter(Scan.verdict == verdict_filter)

    if search_query:
        query = query.filter(Scan.url.ilike(f"%{search_query}%"))

    pagination = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=15, error_out=False)

    return render_template(
        "history.html",
        pagination=pagination,
        scans=pagination.items,
        current_verdict=verdict_filter,
        search_query=search_query
    )
