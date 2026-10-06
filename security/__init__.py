"""
PhishGuard Live Security Module.
Provides deterministic static URL analysis, threat scoring, and SOC auditing.
"""
from security.url_analyzer import extract_features
from security.threat_scoring import compute_threat_score
from security.phishing_detector import PhishingDetector
from security.security_logger import (
    get_client_ip,
    get_client_user_agent,
    log_security_event,
    trigger_security_alert
)

__all__ = [
    "extract_features",
    "compute_threat_score",
    "PhishingDetector",
    "get_client_ip",
    "get_client_user_agent",
    "log_security_event",
    "trigger_security_alert"
]
