# 🎓 PhishGuard Live — Academic Evaluation & Live Demonstration Guide

This guide provides a step-by-step presentation script to demonstrate PhishGuard Live during college evaluation, technical vivas, or project reviews.

---

## ⏱️ 5-Minute Demonstration Plan

| Time | Phase | Target Screen | Objective |
| :--- | :--- | :--- | :--- |
| **0:00 - 1:00** | Introduction & Problem | Slide / Dashboard | Explain phishing epidemic and why static URL analysis avoids SSRF vulnerabilities. |
| **1:00 - 2:00** | Live Threat Scanner | `/scanner` | Scan 3 representative URLs (Safe, Suspicious, Phishing). Show deterministic score and indicators. |
| **2:00 - 3:00** | Live SOC Dashboard | `/dashboard` | Show live Chart.js throughput, PostgreSQL aggregations, and real-time audit trail. |
| **3:00 - 4:00** | Two-Device Integration | Phone & CLI Agent | Scan a URL from a secondary device (laptop terminal or phone) and show instant dashboard synchronization. |
| **4:00 - 5:00** | Admin & Compliance | `/admin` & `/reports`| Demonstrate account lockout defense, alert triage, and CSV audit report download. |

---

## 🎬 Step-by-Step Viva Execution Script

### Phase 1: Authentication & Threat Landscape
1. Open the public Render HTTPS URL in your presentation browser:
   `https://YOUR-APP.onrender.com/login`
2. **Key Talking Point:**
   > *"Notice that our portal enforces HTTPS, strict security headers, and modern salted Scrypt password hashing. We also incorporate automatic account locking after 5 consecutive failed attempts to counter credential stuffing attacks."*
3. Log in with credentials:
   - **Username:** `admin`
   - **Password:** `Admin@PhishGuard2026!`

---

### Phase 2: Live URL Threat Scanner
1. Navigate to **URL Scanner** (`/scanner`).
2. Use the built-in quick test buttons or paste the following 3 demonstration targets:

#### Target A: Benign Legitimate Domain
- **Input URL:** `https://docs.python.org/3/library/urllib.parse.html`
- **Result:** Threat Score `0–10 / 100` | Verdict: `SAFE` | Risk: `LOW`
- **Talking Point:** *"The engine recognizes standard domain lexical patterns, valid TLS protocol, and low Shannon entropy."*

#### Target B: Suspicious Structural Link
- **Input URL:** `http://account-update-portal.top/verification?user=demo`
- **Result:** Threat Score `35–50 / 100` | Verdict: `SUSPICIOUS` | Risk: `MEDIUM`
- **Talking Point:** *"The engine flags the high-risk `.top` TLD, plaintext HTTP, and account urgency vocabulary."*

#### Target C: Deceptive Phishing Campaign
- **Input URL:** `http://paypal.com.verify-billing-update.xyz/login/secure`
- **Result:** Threat Score `85 / 100` | Verdict: `PHISHING` | Risk: `CRITICAL`
- **Talking Point:** *"Here we see brand impersonation (`paypal`), multiple subdomain layers, security keyword injection, and the `.xyz` TLD. The system automatically triggers a CRITICAL security alert in PostgreSQL!"*

---

### Phase 3: Real-Time SOC Dashboard & Analytics
1. Navigate to **Dashboard** (`/dashboard`).
2. Point out:
   - **Telemetry Cards:** Total Scans, Safe, Suspicious, Phishing, Active Alerts. Every number is queried live from PostgreSQL (`func.count()`).
   - **Scan Activity Chart:** Rendered dynamically using Chart.js over a 7-day rolling window.
   - **Threat Classification Doughnut:** Real-time distribution between safe, suspicious, and phishing targets.
   - **Security Audit Trail:** Shows instant logs of every scan, IP address, and security event.

---

### Phase 4: External Multi-Device Demonstration (High Evaluator Impact!)
1. Open your **Mobile Phone** browser.
2. Navigate to your live public Render URL: `https://YOUR-APP.onrender.com`
3. On your **Laptop Terminal**, execute the standalone Python agent:
   ```bash
   python agent/phishguard_agent.py --api-url "https://YOUR-APP.onrender.com" "http://login.appleid.apple.com.auth-update.fit/account/confirm"
   ```
4. Observe the terminal output rendering the colored threat assessment report.
5. Immediately refresh your phone browser or desktop dashboard:
   - **The scan appears instantly in the recent scans table!**
   - **A corresponding security event is logged with the laptop's client IP!**
6. **Key Talking Point:**
   > *"This proves true cross-network cloud operation: Device 1 (phone) and Device 2 (laptop) communicate through our live cloud API and synchronize across the PostgreSQL database."*

---

### Phase 5: Incident Triage & Compliance Export
1. Navigate to **Security Alerts** (`/alerts`):
   - Show how the phishing scan automatically triggered an `OPEN` alert.
   - Click **Resolve** to change status to `RESOLVED`.
2. Navigate to **Reports** (`/reports`):
   - Review detection rate and prevalent threat signatures.
   - Click **Export Threat Logs (.CSV)** to demonstrate compliance audit readiness.
3. Show **API Documentation** (`/api-docs`):
   - Demonstrate the complete cURL examples and JSON response schemas.
