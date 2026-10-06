"""
Threat Intelligence and Analytics Reporting Routes.
Generates aggregated SOC intelligence metrics and CSV compliance exports.
"""
import csv
import io
from collections import Counter
from flask import Blueprint, render_template, Response, request, session
from sqlalchemy import func
from models import db, Scan
from routes.auth import login_required

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/reports")
@login_required
def reports():
    total_scans = db.session.query(func.count(Scan.id)).scalar() or 0
    safe_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "SAFE").scalar() or 0
    suspicious_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "SUSPICIOUS").scalar() or 0
    phishing_scans = db.session.query(func.count(Scan.id)).filter(Scan.verdict == "PHISHING").scalar() or 0

    safe_pct = round((safe_scans / total_scans * 100), 1) if total_scans else 0.0
    suspicious_pct = round((suspicious_scans / total_scans * 100), 1) if total_scans else 0.0
    phishing_pct = round((phishing_scans / total_scans * 100), 1) if total_scans else 0.0
    detection_rate = round(((suspicious_scans + phishing_scans) / total_scans * 100), 1) if total_scans else 0.0

    severity_counts = {
        "LOW": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "LOW").scalar() or 0,
        "MEDIUM": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "MEDIUM").scalar() or 0,
        "HIGH": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "HIGH").scalar() or 0,
        "CRITICAL": db.session.query(func.count(Scan.id)).filter(Scan.risk_level == "CRITICAL").scalar() or 0
    }

    # Aggregate Top Indicators across recent scans
    recent_threat_scans = Scan.query.filter(Scan.verdict.in_(["SUSPICIOUS", "PHISHING"])).order_by(Scan.created_at.desc()).limit(100).all()
    indicator_counter = Counter()
    for scan in recent_threat_scans:
        for ind in scan.get_indicators():
            if isinstance(ind, dict) and "name" in ind:
                indicator_counter[ind["name"]] += 1
            elif isinstance(ind, str):
                indicator_counter[ind] += 1

    top_indicators = indicator_counter.most_common(8)

    # Top Recent Threats
    recent_threats = Scan.query.filter(Scan.verdict.in_(["SUSPICIOUS", "PHISHING"])).order_by(Scan.created_at.desc()).limit(10).all()

    return render_template(
        "reports.html",
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        phishing_scans=phishing_scans,
        safe_pct=safe_pct,
        suspicious_pct=suspicious_pct,
        phishing_pct=phishing_pct,
        detection_rate=detection_rate,
        severity_counts=severity_counts,
        top_indicators=top_indicators,
        recent_threats=recent_threats
    )

@reports_bp.route("/reports/export-csv")
@login_required
def export_csv():
    """Generates downloadable CSV file of all scan logs for audit compliance."""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Timestamp (UTC)", "Target URL", "Threat Score", "Verdict",
        "Risk Level", "Source", "Client IP", "Indicators Count"
    ])

    for s in scans:
        writer.writerow([
            s.id,
            s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else "",
            s.url,
            s.threat_score,
            s.verdict,
            s.risk_level,
            s.source,
            s.client_ip or "N/A",
            len(s.get_indicators())
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishguard_threat_report.csv"}
    )
