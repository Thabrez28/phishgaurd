import json
from models import db, utc_now

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    url = db.Column(db.Text, nullable=False)
    normalized_url = db.Column(db.Text, nullable=False, index=True)
    threat_score = db.Column(db.Integer, nullable=False, index=True)
    verdict = db.Column(db.String(20), nullable=False, index=True)  # SAFE, SUSPICIOUS, PHISHING
    risk_level = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    analysis_reasons = db.Column(db.Text, nullable=True)  # JSON-encoded array of reasons/indicators
    client_ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    source = db.Column(db.String(32), default="web", nullable=False)  # web, api, agent, demo
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)


    # Relationships
    alerts = db.relationship("Alert", backref="scan", lazy="dynamic", cascade="all, delete-orphan")

    def get_indicators(self):
        """Returns list of indicators parsed from JSON text."""
        if not self.analysis_reasons:
            return []
        try:
            return json.loads(self.analysis_reasons)
        except Exception:
            return [self.analysis_reasons]

    def set_indicators(self, indicators_list):
        """Encodes list of indicators into JSON text."""
        self.analysis_reasons = json.dumps(indicators_list)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "threat_score": self.threat_score,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "indicators": self.get_indicators(),
            "source": self.source,
            "client_ip": self.client_ip,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Scan #{self.id} {self.verdict} ({self.threat_score}/100)>"
