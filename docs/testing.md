# 🧪 PhishGuard Live — Test Strategy & Pytest Results

## 1. Quality Assurance Strategy
PhishGuard Live employs automated test suites executed via `pytest`. The test suite covers four distinct domains:
1. **Authentication & RBAC:** Password hashing, user creation, session authentication, account lockout, role-based access.
2. **Detection Engine & Heuristics:** Shannon entropy, lexical feature extraction, brand spoofing rules, scoring determinism.
3. **RESTful API:** Health checks, telemetry feeds, JSON contract validation, bad input handling.
4. **Security Protections:** Security headers, custom 404/403 handlers, SQL injection resilience, audit logging.

---

## 2. Test Execution & Results

### Command
```bash
python -m pytest tests/ -v
```

### Test Results Summary
```
============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-9.1.1, pluggy-1.6.0
rootdir: T:\my project\phishgaurd live
collected 23 items

tests/test_api.py::test_api_health PASSED                                [  4%]
tests/test_api.py::test_api_scan_safe_endpoint PASSED                    [  8%]
tests/test_api.py::test_api_scan_phishing_endpoint PASSED                [ 13%]
tests/test_api.py::test_api_scan_invalid_input PASSED                    [ 17%]
tests/test_api.py::test_api_stats_endpoint PASSED                        [ 21%]
tests/test_api.py::test_api_scans_and_alerts_endpoints PASSED            [ 26%]
tests/test_auth.py::test_password_hashing PASSED                         [ 30%]
tests/test_auth.py::test_user_registration PASSED                        [ 34%]
tests/test_auth.py::test_registration_mismatched_password PASSED         [ 39%]
tests/test_auth.py::test_login_and_logout PASSED                         [ 43%]
tests/test_auth.py::test_failed_login_and_lockout PASSED                 [ 47%]
tests/test_auth.py::test_admin_route_protection PASSED                   [ 52%]
tests/test_scanner.py::test_url_validation PASSED                        [ 56%]
tests/test_scanner.py::test_shannon_entropy PASSED                       [ 60%]
tests/test_scanner.py::test_safe_url_scan PASSED                         [ 65%]
tests/test_scanner.py::test_suspicious_url_scan PASSED                   [ 69%]
tests/test_scanner.py::test_phishing_url_scan PASSED                     [ 73%]
tests/test_scanner.py::test_deterministic_scoring PASSED                 [ 78%]
tests/test_scanner.py::test_scanner_web_workflow PASSED                  [ 82%]
tests/test_security.py::test_security_headers_present PASSED             [ 86%]
tests/test_security.py::test_custom_404_handler PASSED                   [ 91%]
tests/test_security.py::test_sql_injection_resilience PASSED             [ 95%]
tests/test_security.py::test_security_event_logging PASSED               [100%]

====================== 23 passed in 11.78s (100% Pass Rate) ===================
```

---

## 3. Test Cases Specification

| Test File | Test Case Name | Objective | Result |
| :--- | :--- | :--- | :---: |
| `test_api.py` | `test_api_health` | Validates `/api/health` reports status 200 and connected DB | **PASSED** |
| `test_api.py` | `test_api_scan_safe_endpoint` | Validates benign URL returns SAFE verdict and creates API log | **PASSED** |
| `test_api.py` | `test_api_scan_phishing_endpoint` | Validates phishing URL returns score >= 60 and triggers alert | **PASSED** |
| `test_api.py` | `test_api_scan_invalid_input` | Validates bad requests return HTTP 400 Bad Request | **PASSED** |
| `test_api.py` | `test_api_stats_endpoint` | Validates `/api/stats` returns accurate counts | **PASSED** |
| `test_api.py` | `test_api_scans_and_alerts_endpoints` | Validates telemetry feeds return JSON arrays | **PASSED** |
| `test_auth.py` | `test_password_hashing` | Validates Werkzeug scrypt hashing and verification | **PASSED** |
| `test_auth.py` | `test_user_registration` | Validates operator enrollment and database insertion | **PASSED** |
| `test_auth.py` | `test_registration_mismatched_password`| Validates password match validation | **PASSED** |
| `test_auth.py` | `test_login_and_logout` | Validates full authentication lifecycle and session termination | **PASSED** |
| `test_auth.py` | `test_failed_login_and_lockout` | Validates account locks after 5 consecutive failures | **PASSED** |
| `test_auth.py` | `test_admin_route_protection` | Validates non-admin users receive 403 Forbidden | **PASSED** |
| `test_scanner.py`| `test_url_validation` | Validates input checks and rejection of dangerous URI schemes | **PASSED** |
| `test_scanner.py`| `test_shannon_entropy` | Validates Shannon entropy detects DGA randomness | **PASSED** |
| `test_scanner.py`| `test_safe_url_scan` | Validates benign domains receive score < 30 and LOW risk | **PASSED** |
| `test_scanner.py`| `test_suspicious_url_scan` | Validates anomalous URLs receive score 30–59 | **PASSED** |
| `test_scanner.py`| `test_phishing_url_scan` | Validates spoofed brands receive score >= 60 and CRITICAL risk | **PASSED** |
| `test_scanner.py`| `test_deterministic_scoring` | Validates that identical inputs yield strictly identical scores | **PASSED** |
| `test_scanner.py`| `test_scanner_web_workflow` | Validates interactive scanner form submission | **PASSED** |
| `test_security.py`| `test_security_headers_present` | Validates presence of CSP, HSTS, X-Frame-Options, X-Content-Type | **PASSED** |
| `test_security.py`| `test_custom_404_handler` | Validates custom 404 page renders without stack traces | **PASSED** |
| `test_security.py`| `test_sql_injection_resilience` | Validates ORM parametrization resists SQL injection payloads | **PASSED** |
| `test_security.py`| `test_security_event_logging` | Validates security audit trail persistence | **PASSED** |
