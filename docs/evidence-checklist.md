# 📸 PhishGuard Live — Academic Evaluation & Evidence Checklist

Use this checklist to capture and organize screenshots for your final project submission, viva report, and project presentation.

---

## 📋 Comprehensive Screenshot Checklist

| # | Demonstration Item | Target Screen / URL | Recommended File Name | Status |
| :-: | :--- | :--- | :--- | :-: |
| **1** | **SOC Portal Sign In** | `/login` (with demo credentials box) | `01_login_portal.png` | [ ] |
| **2** | **SOC Live Dashboard** | `/dashboard` (Telemetry cards, Chart.js, events) | `02_dashboard_overview.png` | [ ] |
| **3** | **URL Threat Scanner** | `/scanner` (Radar animation & demo pills) | `03_scanner_interface.png` | [ ] |
| **4** | **Safe Scan Analysis** | `/scanner` (Result: Python docs, Score < 30) | `04_scan_result_safe.png` | [ ] |
| **5** | **Suspicious Scan Analysis** | `/scanner` (Result: .top TLD, Score 30-59) | `05_scan_result_suspicious.png`| [ ] |
| **6** | **Phishing Scan Analysis** | `/scanner` (Result: Brand spoof, Score >= 60) | `06_scan_result_phishing.png` | [ ] |
| **7** | **Technical Dossier** | `/result/<id>` (Entropy & structural traits) | `07_technical_dossier.png` | [ ] |
| **8** | **Historical Scan Log** | `/history` (Filtered by verdict with pagination) | `08_scan_history.png` | [ ] |
| **9** | **Security Alerts Triage** | `/alerts` (Active incidents & triage buttons) | `09_security_alerts.png` | [ ] |
| **10**| **Executive Intelligence** | `/reports` (Detection rate, top indicators) | `10_threat_reports.png` | [ ] |
| **11**| **CSV Audit Report** | Downloaded `phishguard_threat_report.csv` | `11_csv_export_excel.png` | [ ] |
| **12**| **REST API Documentation** | `/api-docs` (cURL examples & JSON schemas) | `12_api_documentation.png` | [ ] |
| **13**| **External Device Telemetry**| `/external-device` (Live IP & CLI setup) | `13_external_device_page.png` | [ ] |
| **14**| **External Python CLI Agent**| Terminal running `python phishguard_agent.py` | `14_cli_agent_terminal.png` | [ ] |
| **15**| **Admin Console & Users** | `/admin` (User lockout & DB seeding controls) | `15_admin_console.png` | [ ] |
| **16**| **Custom Error Handling** | `/non-existent` (404 page with cyber styling) | `16_custom_error_404.png` | [ ] |
| **17**| **Pytest Automated Suite** | Terminal running `pytest tests/ -v` (23 passed)| `17_pytest_23_passed.png` | [ ] |
| **18**| **GitHub Repository** | GitHub repo overview with code & README | `18_github_repository.png` | [ ] |
| **19**| **Render Cloud Dashboard** | Render Web Service & PostgreSQL Service | `19_render_dashboard.png` | [ ] |
| **20**| **Mobile Device Access** | Smartphone accessing live Render HTTPS URL | `20_mobile_phone_screen.png` | [ ] |

---

## 💡 Capturing High-Quality Viva Evidence

### Mobile Device Evidence (Item #20)
1. Open Chrome or Safari on your phone.
2. Navigate to your live public Render HTTPS URL.
3. Take a screenshot showing the responsive sidebar collapsed, live UTC clock, and threat score gauge.
4. *Examiners love seeing responsive design working on a real phone!*

### CLI Terminal Evidence (Item #14)
1. Run:
   ```bash
   python agent/phishguard_agent.py "http://paypal.com.verify-billing-update.xyz/login/secure"
   ```
2. Capture the full colored terminal banner showing the threat score, red `[!] PHISHING` verdict, and indicators.

### Automated Test Proof (Item #17)
1. Run:
   ```bash
   python -m pytest tests/ -v
   ```
2. Capture the green output line showing `23 passed (100%)`.
