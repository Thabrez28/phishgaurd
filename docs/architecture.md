# 🏛 PhishGuard Live — System Architecture Specification

## 1. Overview
PhishGuard Live is an enterprise-grade, cloud-native cybersecurity platform architected to detect, analyze, and monitor phishing threats in real time. It employs a **Zero-Trust, Zero-SSRF** philosophy: the server evaluates the structural, lexical, and cryptographic characteristics of URLs without making outbound network connections.

---

## 2. High-Level Architecture Diagram

```
                 +---------------------------------------+
                 |    Remote Client Tier                 |
                 |  - Mobile Smartphone (Safari/Chrome)  |
                 |  - Desktop Workstation Browser        |
                 |  - Standalone Python CLI Agent        |
                 |  - External SIEM / Script via cURL    |
                 +-------------------+-------------------+
                                     | Public HTTPS (Port 443)
                                     v
                 +---------------------------------------+
                 |    Edge Ingress & Infrastructure      |
                 |  - Cloudflare / Render TLS Proxy      |
                 |  - Automatic HTTPS Termination        |
                 |  - DDoS & Port Forwarding             |
                 +-------------------+-------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |    WSGI Application Server Tier       |
                 |  - Gunicorn Multi-Worker HTTP Server  |
                 |  - Worker Heartbeat & Auto-Restart    |
                 +-------------------+-------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |    Flask 3.1 Defensive Core           |
                 |  - App Factory (create_app)           |
                 |  - Flask-Limiter (Brute-force shield) |
                 |  - Security Headers Middleware        |
                 |  - Custom Error Handlers (403/404/500)|
                 +---------+-------------------+---------+
                           |                   |
            +--------------+                   +--------------+
            |                                                 |
            v                                                 v
+-------------------------------+             +-------------------------------+
|  Static Cybersecurity Engine  |             |  PostgreSQL Cloud Persistence |
|  - RFC 3986 Lexical Parser    |             |  - users (RBAC & Lockout)     |
|  - Shannon Entropy Engine     |             |  - scans (Threat Scores)      |
|  - Homograph / Punycode Check |             |  - alerts (Triage Queue)      |
|  - Brand Impersonation Rules  |             |  - security_events (Audit)    |
|  - Weighted Scoring Matrix    |             |  - api_logs (API Telemetry)   |
+-------------------------------+             +-------------------------------+
```

---

## 3. Component Breakdown

### 3.1 Ingress & Server Tier
- **Render HTTPS Edge:** Terminates TLS 1.3 certificates automatically. Routes public traffic to the internal container port `$PORT`.
- **Gunicorn WSGI Server:** Configured via `Procfile` with 3 parallel sync workers, a 120-second timeout, and socket binding to `0.0.0.0:$PORT`.

### 3.2 Application & Routing Tier
- **Application Factory Pattern (`app.py:create_app`):** Isolates state and enables seamless context switching between `production`, `development`, and `testing`.
- **Modular Blueprints:**
  - `auth_bp`: Registration, login, lockout tracking, role-based decorators (`@login_required`, `@admin_required`).
  - `dashboard_bp`: Real-time metric queries, Chart.js integrations, API docs, and external device telemetry.
  - `scanner_bp`: Interactive URL inspection, threat scoring, and scan history pagination.
  - `api_bp`: RESTful endpoints (`/api/health`, `/api/scan`, `/api/stats`, `/api/scans`, `/api/alerts`).
  - `alerts_bp`: Incident triage workflow (`OPEN` -> `INVESTIGATING` -> `RESOLVED`).
  - `reports_bp`: Executive analytics and RFC 4180 CSV compliance export.
  - `admin_bp`: User lifecycle controls, synthetic test data generation, and audit trail inspection.

### 3.3 Defensive Analysis Pipeline
1. **Input Normalization & Sanitization:** Strips whitespace, enforces length caps (2048 characters), rejects prohibited URI schemes (`file://`, `javascript:`, `data:`).
2. **Feature Extraction (`security/url_analyzer.py`):** Computes lexical ratios, dot counts, hyphen counts, port anomalies, TLD classifications, and Shannon domain entropy.
3. **Deterministic Scoring Matrix (`security/threat_scoring.py`):** Applies weighted risk factors, calculates score (0–100), assigns verdict (`SAFE`, `SUSPICIOUS`, `PHISHING`), and risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
4. **Audit & Alert Dispatcher (`security/security_logger.py`):** Automatically registers high-risk scans into the active SOC alert queue.

---

## 4. Data Flow Sequences

### Sequence 1: Web User Scans a Phishing URL
1. Operative submits target URL via `/scanner` form.
2. Form triggers `PhishingDetector.scan(url)`.
3. Engine runs purely static feature extraction (execution time < 5ms).
4. Scan record is inserted into `scans` table with threat score and indicators.
5. If score >= 60, automated trigger generates an alert in `alerts` table (`severity: HIGH/CRITICAL`).
6. A `PHISHING_DETECTED` event is committed to `security_events`.
7. Client renders threat score circle gauge, indicator breakdown, and defensive recommendations.

### Sequence 2: External Python CLI Agent Analyzes a Domain
1. Agent executes `python phishguard_agent.py "http://target.xyz"`.
2. Agent issues HTTP POST request to `/api/scan` on Render cloud.
3. Server validates JSON payload, extracts client IP from `X-Forwarded-For`, processes threat scoring, and logs call into `api_logs`.
4. Server returns JSON response with HTTP 200 OK.
5. CLI agent formats threat score, colored verdict, and indicators to terminal output.
6. The scan immediately appears in the web dashboard on any connected smartphone or laptop.
