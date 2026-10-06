"""
PhishGuard Phishing Detector Coordinator.
Validates URL syntax, normalizes target input, and invokes the static analysis pipeline.
"""
import re
from security.url_analyzer import extract_features
from security.threat_scoring import compute_threat_score

# Basic URL validation regex ensuring host and valid characters
URL_PATTERN = re.compile(
    r"^(?:https?://)?"  # optional scheme
    r"(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})"  # domain or ip
    r"(?::\d{1,5})?"  # optional port
    r"(?:[/?#]\S*)?$",  # optional path/query/fragment
    re.IGNORECASE
)

class PhishingDetector:
    """Core URL detection pipeline."""

    @staticmethod
    def validate_url(url_string: str) -> tuple[bool, str]:
        """
        Validates URL format without performing network DNS or HTTP operations.
        Returns (is_valid, error_message).
        """
        if not url_string or not isinstance(url_string, str):
            return False, "Target URL cannot be empty."

        clean = url_string.strip()
        if len(clean) > 2048:
            return False, "URL length exceeds maximum permitted buffer size (2048 characters)."

        # Reject local dangerous protocols
        lower = clean.lower()
        forbidden_schemes = ["file://", "javascript:", "data:", "vbscript:", "gopher://"]
        for proto in forbidden_schemes:
            if lower.startswith(proto):
                return False, f"Potentially dangerous URI scheme detected: '{proto}'. Only HTTP/HTTPS URLs permitted."

        if not URL_PATTERN.match(clean):
            return False, "Malformed URL format. Please provide a valid hostname (e.g. https://example.com)."

        return True, ""

    @classmethod
    def scan(cls, raw_url: str) -> dict:
        """
        Executes static analysis and threat evaluation on target URL.
        """
        is_valid, error_msg = cls.validate_url(raw_url)
        if not is_valid:
            return {
                "success": False,
                "error": error_msg,
                "threat_score": 0,
                "verdict": "INVALID",
                "risk_level": "UNKNOWN",
                "indicators": [],
                "explanation": error_msg,
                "recommendation": "Provide a valid HTTP or HTTPS URL to scan."
            }

        # Static lexical extraction
        features = extract_features(raw_url)

        # Deterministic scoring
        result = compute_threat_score(features)

        return {
            "success": True,
            "url": raw_url.strip(),
            "normalized_url": features["normalized_url"],
            "features": features,
            "threat_score": result["threat_score"],
            "verdict": result["verdict"],
            "risk_level": result["risk_level"],
            "indicators": result["indicators"],
            "explanation": result["explanation"],
            "recommendation": result["recommendation"]
        }
