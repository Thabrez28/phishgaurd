from models import db, utc_now

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="OPEN", nullable=False, index=True)  # OPEN, INVESTIGATING, RESOLVED
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(64), nullable=True)

    def resolve(self, username="admin"):
        self.status = "RESOLVED"
        self.resolved_at = utc_now()
        self.resolved_by = username


    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by
        }

    def __repr__(self):
        return f"<Alert #{self.id} [{self.severity}] {self.alert_type} - {self.status}>"
