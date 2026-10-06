# 📡 PhishGuard Live — RESTful API Specification

## 1. Overview
The PhishGuard Live REST API enables external automation, SIEM integration, and command-line agent sensors to evaluate URLs programmatically.

- **Base URL:** `https://YOUR-APP.onrender.com/api` (or `http://localhost:5000/api` locally)
- **Data Format:** JSON (`Content-Type: application/json`)
- **Default Rate Limit:** 200 requests / hour, 40 requests / minute per client IP

---

## 2. API Endpoints

### 2.1 Health Check: `GET /api/health`
Verifies backend server availability and PostgreSQL database connectivity.

- **Authentication:** None
- **Rate Limit:** Unrestricted
- **Sample Request:**
  ```bash
  curl -X GET "https://YOUR-APP.onrender.com/api/health"
  ```
- **Responses:**
  - `200 OK`:
    ```json
    {
      "status": "healthy",
      "application": "PhishGuard Live",
      "database": "connected"
    }
    ```
  - `503 Service Unavailable`:
    ```json
    {
      "status": "degraded",
      "application": "PhishGuard Live",
      "database": "disconnected"
    }
    ```

---

### 2.2 Scan Target URL: `POST /api/scan`
Executes deterministic static inspection and threat scoring on target URL.

- **Authentication:** None (Public defensive endpoint)
- **Request Headers:** `Content-Type: application/json`
- **Request Body Parameters:**
  - `url` (string, required): Full target URL to analyze.
- **Sample Request:**
  ```bash
  curl -X POST "https://YOUR-APP.onrender.com/api/scan" \
    -H "Content-Type: application/json" \
    -d '{"url": "http://paypal.com.verify-billing-update.xyz/login/secure"}'
  ```
- **Responses:**
  - `200 OK`:
    ```json
    {
      "success": true,
      "scan_id": 14,
      "url": "http://paypal.com.verify-billing-update.xyz/login/secure",
      "normalized_url": "http://paypal.com.verify-billing-update.xyz/login/secure",
      "threat_score": 85,
      "verdict": "PHISHING",
      "risk_level": "CRITICAL",
      "indicators": [
        {
          "code": "BRAND_SPOOF",
          "name": "Suspected Brand Impersonation (Paypal)",
          "description": "URL targets brand 'Paypal' on an unauthorized domain.",
          "severity": "CRITICAL",
          "weight": 40
        },
        {
          "code": "SUSPICIOUS_TLD",
          "name": "High-Risk TLD (.xyz)",
          "description": "Top-level domain '.xyz' is statistically associated with disposable phishing campaigns.",
          "severity": "MEDIUM",
          "weight": 15
        },
        {
          "code": "SUBDOMAIN_KEYWORDS",
          "name": "Security Keywords in Subdomain",
          "description": "Security/authentication keywords (verify) detected in subdomain hierarchy.",
          "severity": "HIGH",
          "weight": 20
        }
      ],
      "explanation": "PhishGuard detected 3 severe threat indicators...",
      "recommendation": "DANGER: Do NOT click this link, submit credentials, or download attachments.",
      "scanned_at": "2026-10-06T10:45:00.123456"
    }
    ```
  - `400 Bad Request`:
    ```json
    {
      "success": false,
      "error": "Missing or invalid 'url' parameter in JSON payload."
    }
    ```
  - `429 Too Many Requests`:
    ```json
    {
      "success": false,
      "error": "Rate limit exceeded. Please throttle requests."
    }
    ```

---

### 2.3 Aggregate Statistics: `GET /api/stats`
Returns aggregated threat distribution statistics.

- **Sample Request:**
  ```bash
  curl -X GET "https://YOUR-APP.onrender.com/api/stats"
  ```
- **Sample 200 OK Response:**
  ```json
  {
    "success": true,
    "total_scans": 128,
    "safe_scans": 82,
    "suspicious_scans": 24,
    "phishing_scans": 22,
    "active_alerts": 7,
    "detection_rate_pct": 35.9
  }
  ```

---

### 2.4 Recent Scan Feed: `GET /api/scans`
Returns recent scan telemetry.

- **Query Parameters:**
  - `limit` (integer, optional, default: 20, max: 100)
- **Sample Request:**
  ```bash
  curl -X GET "https://YOUR-APP.onrender.com/api/scans?limit=5"
  ```
- **Sample 200 OK Response:**
  ```json
  {
    "success": true,
    "count": 5,
    "scans": [
      {
        "id": 14,
        "url": "http://paypal.com.verify-billing-update.xyz/login/secure",
        "threat_score": 85,
        "verdict": "PHISHING",
        "risk_level": "CRITICAL",
        "source": "api",
        "client_ip": "185.190.140.22",
        "created_at": "2026-10-06T10:45:00.123456"
      }
    ]
  }
  ```

---

### 2.5 Active Alerts Feed: `GET /api/alerts`
Returns queue of open and investigating security alerts for SIEM ingestion.

- **Sample Request:**
  ```bash
  curl -X GET "https://YOUR-APP.onrender.com/api/alerts"
  ```
- **Sample 200 OK Response:**
  ```json
  {
    "success": true,
    "count": 2,
    "alerts": [
      {
        "id": 3,
        "scan_id": 14,
        "alert_type": "PHISHING URL DETECTED",
        "severity": "CRITICAL",
        "message": "Threat engine confirmed phishing indicators on domain...",
        "status": "OPEN",
        "created_at": "2026-10-06T10:45:00.123456"
      }
    ]
  }
  ```
