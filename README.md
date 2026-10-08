<<<<<<< HEAD
# 🔐 PhishGuard Live
### Cloud-Based Phishing URL Detection & Security Operations Monitoring Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Flask 3.1](https://img.shields.io/badge/framework-Flask%203.1-00f2fe.svg)](https://palletsprojects.com/p/flask/)
[![PostgreSQL](https://img.shields.io/badge/database-PostgreSQL-336791.svg)](https://www.postgresql.org/)
[![Render](https://img.shields.io/badge/deployment-Render%20Cloud-46E3B7.svg)](https://render.com/)
[![Tests Passing](https://img.shields.io/badge/pytest-23%20passed%20%7C%20100%25-brightgreen.svg)]()
[![Cybersecurity Level](https://img.shields.io/badge/defensive%20security-Level%205%20Enterprise-critical.svg)]()

> **PhishGuard Live** is an autonomous, full-stack defensive cybersecurity platform that conducts deterministic static structural and lexical threat analysis on URLs in real time. Designed for modern Security Operations Centers (SOC), it delivers live threat classification, automated security alerting, programmatic REST APIs, and seamless external multi-device integration across public networks.

---

## 📋 Table of Contents
1. [Executive Summary & Problem Statement](#-problem-statement)
2. [Key Capabilities & Features](#-key-features)
3. [End-to-End System Architecture](#-system-architecture)
4. [Technology Stack](#-technology-stack)
5. [Deterministic Cybersecurity Engine](#-cybersecurity-engine)
6. [Database Schema (PostgreSQL)](#-database-schema)
7. [RESTful API Telemetry](#-restful-api)
8. [External Multi-Device Integration Demo](#-external-device-integration)
9. [Defensive Security Protections](#-security-protections)
10. [Local Development Quickstart](#-local-setup)
11. [Render Cloud Deployment Guide](#-render-cloud-deployment)
12. [Environment Configuration Reference](#-environment-variables)
13. [Automated Pytest Suite](#-automated-testing)
14. [Documentation Index](#-documentation-index)

---

## 🎯 Problem Statement
Phishing remains the single most prolific entry vector in cyber incidents, accounting for over **3.4 billion daily malicious transmissions**. Attackers increasingly deploy evasive tactics including:
- **Brand impersonation** across lookalike subdomains (e.g., `paypal.com.account-update.xyz`)
- **Punycode / IDN homograph spoofing** (`xn--...`)
- **Domain Generation Algorithms (DGA)** producing high-entropy algorithmic hostnames
- **Hexadecimal / Double URL encoding obfuscation**
- **Direct raw IP addresses** bypassing reputation filters

Traditional dynamic sandboxing and web crawlers introduce severe vulnerabilities—including **Server-Side Request Forgery (SSRF)**, unintentional payload execution, and outbound IP exposure. 

**PhishGuard Live solves this challenge through strict, deterministic static URL analysis.** The server analyzes purely lexical and syntactic structure, extracting 16+ threat heuristics *without ever opening, fetching, or executing the target domain*.

---

## ✨ Key Features
- **Deterministic Threat Scoring (0–100):** Continuous score mapping into `SAFE` (0–29), `SUSPICIOUS` (30–59), and `PHISHING` (60–100) with weighted indicators and actionable defensive recommendations.
- **Enterprise Dark SOC Dashboard:** Built with glassmorphism, responsive cyber layout, live UTC clock, real-time Chart.js telemetry charts, and live database aggregations.
- **Automated Incident Alert Dispatcher:** Real-time generation of alerts categorized into `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` with triage tracking (`OPEN`, `INVESTIGATING`, `RESOLVED`).
- **External Multi-Device Sensor Integration:** Includes standalone CLI agent (`agent/phishguard_agent.py`) capable of transmitting inspection targets to the cloud from any external smartphone, laptop, or IoT device.
- **Role-Based Access Control (RBAC):** Admin and Operator privileges with account lockout defense after 5 consecutive failed attempts.
- **SIEM-Ready RESTful API:** RFC 8259 JSON endpoints (`/api/health`, `/api/scan`, `/api/stats`, `/api/scans`, `/api/alerts`) with rate limiting and automated access auditing.
- **Audit Compliance Export:** Downloadable CSV threat report generation for incident response audits.
- **Synthetic Demonstration Engine:** Pre-loaded harmless evaluation datasets illustrating safe, suspicious, and phishing patterns safely.

---

## 🏛 System Architecture

```
[ External Device 1: Mobile Phone ]        [ External Device 2: Remote Laptop CLI ]
          │ (Browser HTTPS)                            │ (Python CLI Agent / cURL)
          └──────────────────────────┬─────────────────┘
                                     │ Public Internet
                                     ▼
                   ┌───────────────────────────────────┐
                   │        Render Cloud (HTTPS)       │
                   │      Reverse Proxy & SSL/TLS      │
                   └─────────────────┬─────────────────┘
                                     │ PORT / HTTP
                                     ▼
                   ┌───────────────────────────────────┐
                   │    Gunicorn Production Server     │
                   │    (3 Workers, Timeout: 120s)     │
                   └─────────────────┬─────────────────┘
                                     │
                                     ▼
                   ┌───────────────────────────────────┐
                   │     PhishGuard Live (Flask 3.1)   │
                   │  ├── Rate Limiter (Flask-Limiter) │
                   │  ├── Security Headers Middleware  │
                   │  └── RBAC Authentication Layer    │
                   └─────────────────┬─────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────────┐
│   Deterministic Static URL Engine    │  │    PostgreSQL Cloud Database     │
│  ├── Lexical & Structural Extraction │  │  ├── users (RBAC & Lockout)      │
│  ├── Shannon Domain Entropy (DGA)    │  │  ├── scans (Telemetry & Score)   │
│  ├── Brand Spoofing Heuristics       │  │  ├── alerts (SOC Triage Queue)   │
│  ├── Abused TLDs & Insecure Protocol │  │  ├── security_events (Audit Log) │
│  └── Obfuscation & Punycode Engine   │  │  └── api_logs (Inbound Access)   │
└──────────────────────────────────────┘  └──────────────────────────────────┘
```

---

## 🛠 Technology Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Frontend** | HTML5 / CSS3 / Vanilla JS | Custom Dark SOC Theme, Glassmorphism Cards, Cyber Glow Accents |
| **Icons & Fonts** | FontAwesome 6, Inter & JetBrains Mono | Clean cryptographic typography and SOC iconography |
| **Visual Analytics** | Chart.js 4.4 | Real-time scan activity line charts and verdict doughnut distributions |
| **Backend Framework** | Python 3.11+ / Flask 3.1.3 | Modular blueprint architecture, factory pattern (`create_app`) |
| **Database ORM** | Flask-SQLAlchemy 3.1 / SQLAlchemy 2.1 | Parametrized ORM queries, foreign keys, indexes, connection pooling |
| **Migrations** | Flask-Migrate 4.1 / Alembic | Managed schema migration framework |
| **Rate Limiter** | Flask-Limiter 4.1 | Defensive throttling against brute-force and API flooding |
| **Security & Auth** | Werkzeug 3.1 | Scrypt/PBKDF2 salted password hashing, secure session management |
| **Production Server**| Gunicorn 21.2 | Multi-worker WSGI HTTP server |
| **Cloud Hosting** | Render | Managed Web Service & Managed Cloud PostgreSQL |
| **Testing** | Pytest 9.1 | 23 automated tests covering auth, scanner, API, and security |

---

## 🧠 Deterministic Cybersecurity Engine

PhishGuard Live executes strict static feature extraction without network socket connections to target hosts:

```python
# Score Spectrum:
#   0 – 29  : SAFE        (Risk: LOW)
#  30 – 59  : SUSPICIOUS  (Risk: MEDIUM / HIGH)
#  60 – 100 : PHISHING    (Risk: HIGH / CRITICAL)
```

### Evaluated Heuristics & Weighted Scoring:
1. **Raw IP Address as Hostname (+35 pts):** Detects bypass of reputation-based DNS systems (`http://192.168.1.100:8080/login`).
2. **`@` Symbol Credential Obfuscation (+35 pts):** Detects destination deception masking the target authority.
3. **Brand Impersonation (+40 pts):** Identifies unauthorized inclusion of targets (PayPal, Microsoft, Apple, Google, Binance, Netflix, Chase) in secondary subdomains or paths.
4. **Punycode / Homograph Spoofing (+30 pts):** Detects `xn--` internationalized domain name spoofing targeting visually indistinguishable Cyrillic/Greek characters.
5. **High-Risk Disposable TLDs (+15 pts):** Correlates against abused top-level domains (`.xyz`, `.top`, `.tk`, `.buzz`, `.fit`, `.click`, `.loan`, `.country`).
6. **Subdomain Hierarchy Abuse (+10 to +20 pts):** Flags excessive subdomain levels (>= 3 subdomains) typical of multi-tenant phishing kits.
7. **Security Keyword Subdomain Injection (+20 pts):** Scans for deceptive keywords (`login`, `secure`, `verify`, `account`, `banking`) within subdomains.
8. **Multiple Urgency/Harvesting Keywords (+8 to +25 pts):** Evaluates presence of urgency vocabulary (`suspended`, `urgent`, `confirm`, `reward`, `billing`).
9. **Shannon Domain Entropy (+15 pts):** Calculates logarithmic randomness to detect Domain Generation Algorithms (DGA):
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
10. **Hexadecimal & Double Encoding (+15 pts):** Detects `%25` double encoding and hexadecimal obfuscation.
11. **Non-Standard HTTP Ports (+15 pts):** Identifies non-standard rogue ports (`:81`, `:808`, `:2082`, `:8080`, `:8888`).
12. **Insecure Plaintext Protocol (+10 pts):** Elevates baseline risk if sensitive transactions use HTTP without TLS.

---

## 🗄 Database Schema (PostgreSQL)

```
users
 ├── id (PK, Integer)
 ├── username (String 64, Unique, Index)
 ├── email (String 120, Unique, Index)
 ├── password_hash (String 256)
 ├── role (String 20: 'admin' | 'user')
 ├── failed_login_attempts (Integer, Default 0)
 ├── is_locked (Boolean, Default False)
 ├── created_at (DateTime, UTC)
 └── last_login (DateTime, Nullable)

scans
 ├── id (PK, Integer)
 ├── user_id (FK -> users.id, Nullable, Index)
 ├── url (Text)
 ├── normalized_url (Text, Index)
 ├── threat_score (Integer, Index)
 ├── verdict (String 20: 'SAFE' | 'SUSPICIOUS' | 'PHISHING', Index)
 ├── risk_level (String 20: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
 ├── analysis_reasons (Text, JSON Encoded Indicator Array)
 ├── client_ip (String 45)
 ├── user_agent (String 256)
 ├── source (String 32: 'web' | 'api' | 'agent' | 'demo')
 └── created_at (DateTime, UTC, Index)

alerts
 ├── id (PK, Integer)
 ├── scan_id (FK -> scans.id, Nullable, Index)
 ├── alert_type (String 64: 'PHISHING URL DETECTED' | 'RATE LIMIT TRIGGERED' | ...)
 ├── severity (String 20: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', Index)
 ├── message (Text)
 ├── status (String 20: 'OPEN' | 'INVESTIGATING' | 'RESOLVED', Index)
 ├── created_at (DateTime, UTC, Index)
 ├── resolved_at (DateTime, Nullable)
 └── resolved_by (String 64, Nullable)

security_events
 ├── id (PK, Integer)
 ├── user_id (FK -> users.id, Nullable, Index)
 ├── event_type (String 64, Index)
 ├── ip_address (String 45)
 ├── user_agent (String 256)
 ├── description (Text)
 └── created_at (DateTime, UTC, Index)

api_logs
 ├── id (PK, Integer)
 ├── endpoint (String 128, Index)
 ├── method (String 10)
 ├── ip_address (String 45)
 ├── user_agent (String 256)
 ├── response_status (Integer)
 └── created_at (DateTime, UTC, Index)
```

---

## 📡 RESTful API Reference

All API routes return standardized JSON payloads:

### 1. Health Status: `GET /api/health`
```bash
curl -X GET "https://YOUR-APP.onrender.com/api/health"
```
```json
{
  "application": "PhishGuard Live",
  "database": "connected",
  "status": "healthy"
}
```

### 2. Threat Analysis: `POST /api/scan`
```bash
curl -X POST "https://YOUR-APP.onrender.com/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal.com.verify-billing-update.xyz/login/secure"}'
```
```json
{
  "success": true,
  "scan_id": 1,
  "url": "http://paypal.com.verify-billing-update.xyz/login/secure",
  "normalized_url": "http://paypal.com.verify-billing-update.xyz/login/secure",
  "threat_score": 85,
  "verdict": "PHISHING",
  "risk_level": "CRITICAL",
  "indicators": [
    {
      "code": "BRAND_SPOOF",
      "name": "Suspected Brand Impersonation (Paypal)",
      "severity": "CRITICAL",
      "weight": 40
    },
    {
      "code": "SUSPICIOUS_TLD",
      "name": "High-Risk TLD (.xyz)",
      "severity": "MEDIUM",
      "weight": 15
    },
    {
      "code": "SUBDOMAIN_KEYWORDS",
      "name": "Security Keywords in Subdomain",
      "severity": "HIGH",
      "weight": 20
    }
  ],
  "explanation": "PhishGuard detected 3 severe threat indicators...",
  "recommendation": "DANGER: Do NOT click this link, submit credentials, or download attachments.",
  "scanned_at": "2026-10-06T10:45:00.123456"
}
```

### 3. Aggregated Intelligence: `GET /api/stats`
```bash
curl -X GET "https://YOUR-APP.onrender.com/api/stats"
```

### 4. Telemetry Feeds: `GET /api/scans` & `GET /api/alerts`
```bash
curl -X GET "https://YOUR-APP.onrender.com/api/scans?limit=20"
curl -X GET "https://YOUR-APP.onrender.com/api/alerts"
```

---

## 📱 External Device Integration (Two-Device Demo)

PhishGuard Live enables real-time demonstration across independent physical devices:

```
[ DEVICE 1: Phone ]              [ INTERNET ]               [ DEVICE 2: Laptop ]
Browser UI -> Scan URL  ───►  Render HTTPS App  ◄───  CLI Agent / API Scan
          ▲                            │                            ▲
          └─────────── Live PostgreSQL Dashboard Updates ───────────┘
```

### CLI Agent Execution:
```bash
# 1. Point to your deployed Render URL:
export PHISHGUARD_API_URL="https://YOUR-RENDER-DOMAIN.onrender.com"

# 2. Execute inspection:
python agent/phishguard_agent.py "http://suspicious-domain.xyz/verify"
```

---

## 🛡 Security Protections
- **No SSRF / Dynamic Fetching:** The scanner NEVER resolves IP addresses or sends outbound HTTP requests to user-submitted targets.
- **Parametrized SQL Queries:** 100% SQLAlchemy ORM parametrization eliminates SQL injection vectors.
- **Scrypt Password Hashing:** Salted irreversible password derivation using Werkzeug security.
- **Account Lockout Mechanism:** Auto-locking accounts after 5 failed authentication attempts, with security alerts dispatched to the SOC triage queue.
- **Security Response Headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, `Content-Security-Policy`.
- **Defensive Error Handling:** Custom 403, 404, 429, and 500 handlers ensure server internal stack traces are never exposed to clients.

---

## 🚀 Local Setup Quickstart

### Prerequisites
- Python 3.11+
- Git

### 1. Clone & Enter Repository
```bash
git clone https://github.com/Thabrez28/phishguard-live.git
cd phishguard-live
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch Application
```bash
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
Default administrative credentials:
- **Username:** `admin`
- **Password:** `Admin@PhishGuard2026!`

---

## ☁️ Render Cloud Deployment Guide

PhishGuard Live includes pre-configured **Infrastructure-as-Code** specifications:
- `render.yaml` (Render Blueprint definition for Web Service + Managed PostgreSQL)
- `Procfile` (Gunicorn production entrypoint)
- `runtime.txt` (Python runtime pin)

### Step 1: Push Repository to GitHub
```bash
git add .
git commit -m "feat: complete autonomous PhishGuard Live SOC platform"
git push origin main
```

### Step 2: Deploy on Render
1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** -> **Blueprint**.
3. Connect your GitHub repository: `Thabrez28/phishguard-live`.
4. Render automatically parses `render.yaml`, provisions a **PostgreSQL Database**, wires `DATABASE_URL`, builds the Python environment, and launches the web service with Gunicorn.

---

## 🧪 Automated Pytest Suite

Execute the 23-test automated test suite:
```bash
pytest tests/ -v
```

All tests execute in-memory with zero cloud database side-effects:
- ✅ Password hashing & salting
- ✅ User registration & email duplicate rejection
- ✅ Login, logout, and session lifecycle
- ✅ Account lockout defense (5 failed attempts)
- ✅ Admin authorization route restrictions (403 verification)
- ✅ URL validation & protocol blocking (`file://`, `javascript:`)
- ✅ Shannon entropy mathematical calculations
- ✅ Deterministic scoring reproducibility
- ✅ Safe, suspicious, and phishing threat bucket classifications
- ✅ All RESTful endpoints (`/api/health`, `/api/scan`, `/api/stats`, `/api/scans`, `/api/alerts`)
- ✅ Security headers injection
- ✅ Custom 404/403 error page rendering
- ✅ SQL injection resistance
- ✅ Audit logging persistence

---

## 📚 Documentation Index
Comprehensive academic and technical documentation is available in `docs/`:
- [`docs/architecture.md`](docs/architecture.md) — Comprehensive technical architecture specification
- [`docs/api.md`](docs/api.md) — In-depth API integration and telemetry documentation
- [`docs/deployment.md`](docs/deployment.md) — Render cloud deployment runbook & troubleshooting
- [`docs/security.md`](docs/security.md) — Threat models, attack surface analysis, and defensive controls
- [`docs/testing.md`](docs/testing.md) — Test plan, coverage reports, and QA methodology
- [`docs/demo-guide.md`](docs/demo-guide.md) — College evaluation live demo step-by-step walkthrough
- [`docs/presentation.md`](docs/presentation.md) — 10-slide evaluation presentation content
- [`docs/project-report.md`](docs/project-report.md) — Complete 21-section academic final project report
- [`docs/evidence-checklist.md`](docs/evidence-checklist.md) — Visual evidence and evaluation screenshot checklist

---

## 📄 License
This project is developed for defensive cybersecurity research, academic demonstration, and educational purposes.
Unauthorized malicious deployment or scanning of non-consenting infrastructure is strictly prohibited.
=======
# phishgaurd
>>>>>>> origin/main
