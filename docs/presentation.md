# 📊 PhishGuard Live — Presentation Slide Deck (10 Slides)

---

## Slide 1 — Project Title & Overview
### **PHISHGUARD LIVE**
#### Cloud-Based Phishing URL Detection & Security Monitoring Platform
- **Domain:** Defensive Cybersecurity, Cloud Engineering, Full-Stack Architecture
- **Engine Type:** Deterministic Static URL Feature Analysis (Zero-SSRF)
- **Deployment:** Live on Render Cloud with PostgreSQL Persistence
- **Presenter:** Autonomous Cybersecurity Full-Stack Engineer

---

## Slide 2 — Problem Statement
### The Expanding Phishing Attack Surface
- **Pervasive Threat:** Over 3.4 billion malicious emails and URLs circulate daily, driving 90%+ of organizational breaches.
- **Evasion Tactics:** Attackers exploit lookalike subdomains, brand impersonation, Punycode/IDN homograph spoofing, and high-entropy algorithmic domains.
- **Dynamic Crawler Vulnerability:** Traditional scanners that open or fetch target links suffer from **Server-Side Request Forgery (SSRF)**, malware download exposure, and perimeter IP disclosure.

---

## Slide 3 — Proposed Solution
### PhishGuard Live: Deterministic Defensive URL Engine
- **Static Heuristic Inspection:** Pure lexical, structural, and cryptographic analysis of the URL string without connecting to malicious endpoints.
- **Multi-Factor Threat Scoring:** Deterministic 0–100 score mapping URLs into `SAFE`, `SUSPICIOUS`, and `PHISHING`.
- **SOC Operations Platform:** Real-time metrics dashboard, automated incident alerts, and audit trail.
- **Cross-Platform Access:** Accessible from any internet-connected device (phones, laptops, CLI sensors).

---

## Slide 4 — System Architecture
### End-to-End Cloud Flow
```
[ Device 1: Mobile Phone ]        [ Device 2: Remote Laptop CLI ]
          │ (HTTPS)                          │ (API Scan)
          └─────────────────┬────────────────┘
                            ▼
              [ Render Cloud HTTPS Proxy ]
                            ▼
              [ Gunicorn Production Server ]
                            ▼
              [ Flask 3.1 Defensive Engine ]
                   │               │
                   ▼               ▼
      [ Static Detection Engine ]  [ PostgreSQL Database ]
      (Lexical, Entropy, Rules)   (Users, Scans, Alerts, Audit)
```

---

## Slide 5 — Technology Stack
### Production Engineering Foundation
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Glassmorphism SOC Theme, Font Awesome 6.
- **Visual Analytics:** Chart.js 4.4 (Live scan activity & verdict distribution).
- **Backend Core:** Python 3.11+ / Flask 3.1, Flask-SQLAlchemy 3.1, Flask-Migrate, Flask-Limiter.
- **Security & Cryptography:** Werkzeug Scrypt/PBKDF2 salted hashing, OWASP security headers.
- **Database:** PostgreSQL (with automatic connection adaptation for Render).
- **Production Server:** Gunicorn WSGI with 3 sync workers.
- **Automated Testing:** Pytest 9.1 (23 unit and integration tests, 100% pass rate).

---

## Slide 6 — Cybersecurity Detection Engine
### 16+ Deterministic Threat Heuristics
1. **Raw IP Address Host:** Bypasses standard DNS reputation (`+35 pts`).
2. **`@` Symbol Credential Obfuscation:** Conceals real destination (`+35 pts`).
3. **Brand Impersonation:** Spoofing PayPal, Apple, Microsoft, Google, etc. (`+40 pts`).
4. **Punycode / Homograph Attack:** Lookalike Cyrillic characters via `xn--` (`+30 pts`).
5. **High-Risk Disposable TLDs:** `.xyz`, `.top`, `.tk`, `.buzz`, `.fit` (`+15 pts`).
6. **Excessive Subdomain Hierarchy:** >= 3 subdomains (`+20 pts`).
7. **Shannon Domain Entropy:** Detects machine-generated domains (DGA) (`+15 pts`).
8. **Hex / Double Encoding Obfuscation:** Detects `%25` bypasses (`+15 pts`).
9. **Urgency Keywords:** `login`, `verify`, `account`, `suspended`, `wallet` (`+8 to +25 pts`).

---

## Slide 7 — Dashboard & REST API
### Real-Time SOC Telemetry & Programmatic Feeds
- **Live SOC Dashboard:**
  - Live PostgreSQL counters (Total Scans, Safe, Suspicious, Phishing, Active Alerts).
  - 7-Day scan throughput timeline and verdict doughnut charts.
  - Real-time perimeter security audit trail.
- **RESTful JSON API:**
  - `GET /api/health` — Continuous uptime and DB health check.
  - `POST /api/scan` — Programmatic URL scanning for SIEM integration.
  - `GET /api/stats` — Live threat statistics.
  - `GET /api/scans` & `GET /api/alerts` — Incident ingestion streams.

---

## Slide 8 — External Device Integration
### Live Two-Device Cross-Network Verification
- **Any Physical Device:** Mobile phones, remote workstations, IoT appliances, and servers communicate through public HTTPS.
- **Standalone CLI Agent (`phishguard_agent.py`):**
  - Portable, zero-credential Python script.
  - Dispatches target URL to Render cloud API.
  - Renders formatted, color-coded threat dossier to terminal.
- **Instant Cross-Sync:** Scans executed on Device 2 instantly appear on Device 1's browser dashboard via PostgreSQL.

---

## Slide 9 — Live Deployment & Results
### Verified Production Cloud Metrics
- **Deployment Platform:** Render Cloud Platform with Managed PostgreSQL.
- **Zero Localhost Reliance:** 100% cloud-hosted with public HTTPS certificate.
- **Pytest Suite:** 23 / 23 Tests Passed (Authentication, Scanner, API, Security).
- **Performance:** Sub-50ms static scan latency; resilient under rate limiting.
- **Audit Compliance:** Real-time CSV export with full indicator traceability.

---

## Slide 10 — Future Scope & Conclusion
### Roadmap & Academic Conclusion
- **Future Enhancements:**
  - Machine learning ensemble (Random Forest / XGBoost) trained on Lexical datasets.
  - Certificate Transparency (CT) log streaming.
  - Browser extension plugin for Chrome/Firefox.
- **Conclusion:**
  PhishGuard Live successfully delivers an autonomous, full-stack, enterprise-ready Level 5 cybersecurity defensive platform combining static heuristics, cloud persistence, and multi-device interoperability.
