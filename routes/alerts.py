"""
Security Alerts and Incident Management Routes.
Allows security analysts and admins to monitor, triage, and resolve security alerts.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, Alert
from security.security_logger import log_security_event
from routes.auth import login_required

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts")
@login_required
def list_alerts():
    status_filter = request.args.get("status", "").strip().upper()
    severity_filter = request.args.get("severity", "").strip().upper()

    query = Alert.query

    if status_filter in ["OPEN", "INVESTIGATING", "RESOLVED"]:
        query = query.filter(Alert.status == status_filter)
    if severity_filter in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        query = query.filter(Alert.severity == severity_filter)

    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()

    # Summary metrics
    counts = {
        "OPEN": Alert.query.filter_by(status="OPEN").count(),
        "INVESTIGATING": Alert.query.filter_by(status="INVESTIGATING").count(),
        "RESOLVED": Alert.query.filter_by(status="RESOLVED").count(),
        "CRITICAL": Alert.query.filter_by(severity="CRITICAL", status="OPEN").count()
    }

    return render_template(
        "alerts.html",
        alerts=alerts,
        counts=counts,
        current_status=status_filter,
        current_severity=severity_filter
    )

@alerts_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_status(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get("status", "").strip().upper()
    username = session.get("username", "Analyst")

    if new_status in ["OPEN", "INVESTIGATING", "RESOLVED"]:
        old_status = alert.status
        alert.status = new_status
        if new_status == "RESOLVED":
            alert.resolve(username)
        db.session.commit()

        log_security_event(
            event_type="ALERT_STATUS_CHANGED",
            description=f"Alert #{alert.id} ({alert.alert_type}) transitioned from {old_status} to {new_status} by {username}",
            user_id=session.get("user_id")
        )
        flash(f"Alert #{alert.id} status updated to {new_status}.", "success")
    else:
        flash("Invalid status specified.", "danger")

    return redirect(url_for("alerts.list_alerts"))
