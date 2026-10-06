# 🛡 PhishGuard Live — Cybersecurity Architecture & Defensive Controls

## 1. Threat Modeling & Scope
PhishGuard Live is an enterprise defensive security solution designed to counter credential theft, brand spoofing, and malicious link dispersion.

```
                    POTENTIAL ATTACK VECTORS & PHISHGUARD DEFENSES
+------------------------------------+--------------------------------------------+
| Attack Vector                      | PhishGuard Live Defensive Mitigation       |
+------------------------------------+--------------------------------------------+
| Server-Side Request Forgery (SSRF) | Zero Outbound Network Connections          |
| Malware Delivery / Exploit Kits    | Strict Static Lexical & Syntactic Parsing  |
| SQL Injection (SQLi)               | Parametrized SQLAlchemy ORM Queries        |
| Credential Brute-Force & Guessing  | Flask-Limiter Throttling + Account Lockout |
| Password Compromise                | Werkzeug Scrypt/PBKDF2 Salted Hashing      |
| Cross-Site Scripting (XSS)         | Jinja2 Autoescaping + Content-Security-Pol.|
| Clickjacking                       | X-Frame-Options: DENY                      |
| MIME Sniffing                      | X-Content-Type-Options: nosniff            |
| API Flooding / Denial-of-Service   | Fixed-Window Rate Limiting (200 req/hr)    |
| Stack Trace Reconnaissance         | Sanitized Custom 403, 404, 429, 500 Pages  |
+------------------------------------+--------------------------------------------+
```

---

## 2. Defensive Controls Implementation

### 2.1 Complete SSRF Elimination
Dynamic URL crawlers typically resolve DNS, fetch HTTP responses, and parse HTML. This introduces severe attack vectors:
- **SSRF:** Attackers submit `http://169.254.169.254/latest/meta-data/` to harvest cloud IAM credentials.
- **Port Scanning:** Attackers submit `http://127.0.0.1:5432` to discover internal database ports.
- **Malware Drops:** Visiting malicious URLs risks payload execution or server compromise.

**PhishGuard Mitigation:**
The application uses strict **Static Lexical and Syntactic Parsing**. The server NEVER connects to, resolves, or retrieves data from submitted URLs. Only the URL string structure itself is inspected.

### 2.2 Password Security & Cryptographic Storage
Passwords are never stored in plaintext:
- Hashed using Werkzeug's modern Scrypt/PBKDF2 implementation with unique per-user cryptographic salts.
- Password complexity enforced at registration (minimum 8 characters, letters and numbers required).

### 2.3 Account Lockout Defense
- Failed authentication attempts are tracked per user in the PostgreSQL database.
- If 5 consecutive failed logins occur:
  1. The user account is automatically flagged `is_locked = True`.
  2. Further login attempts are immediately rejected.
  3. A high-severity security alert (`MULTIPLE FAILED LOGIN ATTEMPTS`) is triggered in the SOC alert queue.
  4. Only an administrator can unlock the account via `/admin`.

### 2.4 Rate Limiting & Denial-of-Service Shield
Configured via `Flask-Limiter`:
- Standard endpoints: 200 requests/hour, 40 requests/minute per client IP.
- Rate-limit violations return standard HTTP 429 status codes, log a `RATE_LIMIT_TRIGGERED` audit event, and create a security alert.

### 2.5 HTTP Response Security Headers
Injected into every response via Flask middleware:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self';
```

### 2.6 Production Cookie Security
- `SESSION_COOKIE_HTTPONLY = True` (mitigates JavaScript credential theft)
- `SESSION_COOKIE_SAMESITE = 'Lax'` (mitigates Cross-Site Request Forgery)
- `SESSION_COOKIE_SECURE = True` in production (enforces transmission exclusively over HTTPS)
