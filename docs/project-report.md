# 📑 PhishGuard Live — Engineering Project Report
### Cloud-Based Phishing URL Detection & Security Operations Monitoring Platform

---

## 1. Abstract
The proliferation of deceptive hyperlink vectors—commonly known as phishing—constitutes a primary entry mechanism for enterprise intrusions, ransomware, and credential harvesting. Traditional detection systems relying on active dynamic web crawlers frequently introduce severe operational hazards, including Server-Side Request Forgery (SSRF), inadvertent malware execution, and high computational latency. This project presents **PhishGuard Live**, an autonomous, cloud-native, full-stack cybersecurity platform delivering real-time deterministic static URL analysis. By evaluating lexical properties, structural hierarchies, Shannon domain entropy, and brand impersonation heuristics without visiting or resolving target domains, PhishGuard Live achieves zero-SSRF defensive threat analysis with sub-50ms latency. The system features a responsive Security Operations Center (SOC) dashboard, role-based access control with account lockout defense, automated incident alert triage, an RFC 8259 RESTful API, and cross-platform multi-device integration demonstrated between mobile endpoints and standalone CLI agents. The application is deployed live on Render Cloud backed by a managed PostgreSQL database.

---

## 2. Introduction
Phishing attacks have evolved from rudimentary spoofed emails into sophisticated, distributed campaigns leveraging internationalized homograph domains (Punycode), Domain Generation Algorithms (DGA), multi-level subdomains, and obfuscated routing protocols. Securing enterprise perimeters requires threat intelligence platforms that can evaluate suspect URLs rapidly, deterministically, and safely. PhishGuard Live was engineered to bridge the gap between academic threat detection algorithms and production-grade SOC operations by implementing an end-to-end cloud platform featuring live telemetry, persistent PostgreSQL indexing, and automated incident escalation.

---

## 3. Problem Statement
Contemporary URL scanning mechanisms suffer from three critical architectural deficiencies:
1. **SSRF and Execution Hazards:** Automated crawlers that fetch web pages are vulnerable to Server-Side Request Forgery against cloud metadata endpoints (`http://169.254.169.254`) and can be coerced into downloading malicious payloads.
2. **Dynamic Cloaking Evasion:** Modern phishing kits employ IP and User-Agent filtering, serving benign content to automated security scanners while displaying credential-harvesting portals exclusively to target victims.
3. **Operational Silos:** Security detection is often decoupled from operational dashboards and incident response workflows, delaying threat mitigation.

---

## 4. Objectives
- Engineer a **Zero-SSRF Static Analysis Engine** evaluating URLs purely through lexical, structural, and cryptographic heuristics.
- Develop a **Deterministic Scoring Matrix (0–100)** mapping threats into `SAFE`, `SUSPICIOUS`, and `PHISHING` classifications with actionable defensive recommendations.
- Build a **SOC-Grade Dark Theme User Interface** incorporating glassmorphism, responsive navigation, and real-time Chart.js visual analytics.
- Implement **Role-Based Access Control (RBAC)**, salted password hashing, and brute-force account lockout defenses.
- Expose a **High-Performance RESTful API** enabling external SIEM and programmatic ingestion.
- Demonstrate **Multi-Device Cross-Network Interoperability** via mobile browsers and a standalone Python CLI agent.
- Deploy the platform to **Render Cloud** backed by a **Managed PostgreSQL Database**.

---

## 5. Existing System vs. Proposed System

| Dimension | Traditional Dynamic Scanners | PhishGuard Live Proposed System |
| :--- | :--- | :--- |
| **Inspection Method** | Outbound HTTP requests & DOM rendering | Pure static lexical & structural analysis |
| **SSRF Risk** | **Critical** (Vulnerable to metadata harvesting) | **Zero** (No outbound server connections) |
| **Latency** | High (1500ms – 6000ms per scan) | Ultra-low (< 50ms per scan) |
| **Evasion Vulnerability** | Susceptible to IP cloaking and bot filters | Immune to client-side cloaking |
| **Multi-Device Support**| Restricted to browser extensions | Cross-platform (Web, CLI agent, REST API) |
| **Storage Architecture**| Ephemeral or local flat files | Managed cloud PostgreSQL with indexes |

---

## 6. System Architecture
PhishGuard Live follows a modular layered architecture comprising the Client Tier, Edge Proxy Tier, WSGI Application Tier, Defensive Engine Core, and Cloud Persistence Tier. All inbound web traffic terminates TLS at the Render edge proxy and is forwarded to Gunicorn sync workers. The Flask core processes authentication, rate limiting, and routing, invoking the static detection engine before persisting telemetry to PostgreSQL.

---

## 7. Technology Stack
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Custom SOC Dark Glassmorphism, Font Awesome 6.
- **Data Visualization:** Chart.js 4.4 (Scan throughput line charts and verdict distributions).
- **Backend Framework:** Python 3.11+ / Flask 3.1.3, Flask-SQLAlchemy 3.1, Flask-Migrate 4.1, Flask-Limiter 4.1.
- **Cryptography & Security:** Werkzeug Scrypt/PBKDF2 salted password hashing, OWASP security headers.
- **Database:** PostgreSQL (with automatic SQLAlchemy connection string adaptation).
- **Production Server:** Gunicorn 21.2 (3 sync workers, timeout 120s).
- **Cloud Infrastructure:** Render Cloud Platform (Web Service & Managed Database).
- **Testing:** Pytest 9.1 (23 unit and integration test cases, 100% pass rate).

---

## 8. Functional Requirements
- **FR1 (User Management):** Operative registration, login, logout, password hashing, and session management.
- **FR2 (Static URL Inspection):** Validation and parsing of target URLs without outbound network activity.
- **FR3 (Threat Scoring):** Deterministic computation of threat scores (0–100), risk levels, and indicator lists.
- **FR4 (Real-Time Dashboard):** Display of live database statistics, recent scans, and security audit events.
- **FR5 (Incident Alerting):** Automated dispatching of alerts for phishing and high-risk scans with status lifecycle (`OPEN`, `INVESTIGATING`, `RESOLVED`).
- **FR6 (RESTful API):** JSON endpoints for health checks, scanning, aggregate statistics, and telemetry streams.
- **FR7 (External CLI Agent):** Command-line client capable of querying the cloud API from remote terminals.
- **FR8 (Compliance Export):** Generation of downloadable CSV audit records.

---

## 9. Non-Functional Requirements
- **NFR1 (Security):** Zero outbound connections to user-submitted targets; protection against SQLi, XSS, CSRF, and brute force.
- **NFR2 (Performance):** Static analysis processing time under 50ms.
- **NFR3 (Reliability):** 99.9% uptime with automated database connection pooling and health check monitoring.
- **NFR4 (Responsiveness):** Fluid layout compatibility across mobile smartphones, tablets, and desktop workstations.
- **NFR5 (Maintainability):** Modular blueprint architecture and automated database migration support.

---

## 10. Database Design & Schema
The relational schema is implemented in PostgreSQL with foreign key constraints, cascading deletes, and strategic B-tree indexing:
- `users`: User authentication, roles (`admin`, `user`), failed login attempts, lockout flags, and login timestamps.
- `scans`: Target URLs, normalized URLs, threat scores, verdicts, risk levels, JSON indicator arrays, and client IPs.
- `alerts`: Scan associations, alert types, severity ratings (`LOW` to `CRITICAL`), triage status, and resolution metadata.
- `security_events`: Detailed audit logs of system activities (logins, lockouts, scans, alerts).
- `api_logs`: Request telemetry recording endpoints, HTTP methods, client IPs, and status codes.

---

## 11. RESTful API Design
All endpoints implement RFC 8259 compliant JSON responses:
- `GET /api/health` — Verifies application health and database connection.
- `POST /api/scan` — Programmatic static inspection endpoint.
- `GET /api/stats` — Aggregate metrics and detection ratios.
- `GET /api/scans` — Historical scan feed with limit parameters.
- `GET /api/alerts` — Incident management queue feed.

---

## 12. Cybersecurity Methodology & Threat Scoring
The detection engine calculates a cumulative risk score:
$$\text{Threat Score} = \min\left(100, \sum_{i=1}^{m} w_i \cdot I_i\right)$$
Where $w_i$ represents indicator weights and $I_i \in \{0, 1\}$ denotes indicator activation.
- **IP Address as Hostname:** $+35$ points
- **`@` Symbol Obfuscation:** $+35$ points
- **Brand Impersonation:** $+40$ points
- **Punycode / Homograph Spoofing:** $+30$ points
- **High-Risk Disposable TLDs:** $+15$ points
- **Subdomain Hierarchy Abuse (>= 3):** $+20$ points
- **Subdomain Keyword Injection:** $+20$ points
- **Shannon Domain Entropy (>= 3.8):** $+15$ points
- **Hexadecimal / Double Encoding:** $+15$ points
- **Urgency / Harvesting Keywords:** $+8$ to $+25$ points

---

## 13. Authentication & Access Control
- Passwords derive cryptographic hashes via Werkzeug Scrypt/PBKDF2 with unique salts.
- Consecutive failed login attempts trigger progressive defensive controls: at 5 failed attempts, the account is locked and a high-severity alert is dispatched.
- View authorization is enforced via Python decorators (`@login_required` and `@admin_required`).

---

## 14. Defensive Security Controls
- **Zero-SSRF Architecture:** Strictly lexical inspection eliminates internal network scanning vectors.
- **SQLi Protection:** 100% SQLAlchemy ORM parametrization.
- **Rate Limiting:** Fixed-window client IP rate limiting via `Flask-Limiter`.
- **Security Headers:** Injected `nosniff`, `DENY` clickjacking protection, CSP, and strict referrer policies.
- **Information Masking:** Custom error handlers (403, 404, 429, 500) prevent stack trace exposure.

---

## 15. External Device Integration
The platform demonstrates distributed telemetry through two physical devices:
1. **Device 1 (Mobile Smartphone):** Operates the web application interface via public HTTPS.
2. **Device 2 (Secondary Laptop):** Executes `agent/phishguard_agent.py` or automated cURL scripts targeting the cloud `/api/scan` endpoint.
Both devices synchronize state in real time through the central PostgreSQL database.

---

## 16. Cloud Deployment
Deployment is configured on Render Cloud utilizing declarative Infrastructure-as-Code (`render.yaml`). The environment establishes:
- A Python 3.11 web service executing Gunicorn with 3 sync workers.
- A managed PostgreSQL instance linked dynamically via the `DATABASE_URL` environment variable.
- Automated URL adaptation converting `postgres://` into SQLAlchemy-compliant `postgresql://`.

---

## 17. Testing & Verification
A 23-test automated test suite was developed using `pytest`. The suite tests:
- Cryptographic password hashing and verification.
- User registration, duplicate email rejection, and authentication lockout.
- URL syntax validation and rejection of dangerous URI schemes (`file://`, `javascript:`).
- Shannon entropy calculations and determinism across repeated executions.
- Threat score classification thresholds (`SAFE`, `SUSPICIOUS`, `PHISHING`).
- All REST API endpoints and telemetry logging.
- Security headers and custom error page rendering.
- **Execution Result:** 23 passed, 0 failed, 100% test pass rate.

---

## 18. Results & Performance
- **Static Inspection Latency:** Mean analysis time is 18ms.
- **SSRF Vulnerability:** 0% exposure.
- **False Positive Handling:** Verified against standard top-level legitimate domains (Python, GitHub, Wikipedia).
- **Cross-Device Throughput:** External CLI agent requests process and reflect on the web dashboard within 150ms.

---

## 19. Limitations
- Pure static lexical analysis does not inspect dynamic JavaScript execution or DOM modifications.
- Obfuscated shorteners (e.g., `bit.ly`) require URL unshortening resolution for deep structural analysis.

---

## 20. Future Scope
- Integration of a supervised machine learning classifier (Random Forest / XGBoost) trained on massive phishing corpuses.
- Real-time DNS Certificate Transparency (CT) log streaming.
- Native browser extension for client-side automated interception.

---

## 21. Conclusion
PhishGuard Live successfully demonstrates an autonomous, defensive Level 5 cybersecurity platform. By coupling deterministic static heuristics with enterprise SOC monitoring, cloud database persistence, and multi-device API interoperability, the system provides effective, zero-SSRF URL threat intelligence suitable for enterprise and academic deployment.
