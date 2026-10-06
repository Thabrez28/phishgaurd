# ☁️ PhishGuard Live — Cloud Deployment Runbook (Render & PostgreSQL)

## 1. Prerequisites
- GitHub Account
- Render Account ([https://render.com](https://render.com))
- Git installed on your workstation

---

## 2. Infrastructure-as-Code Configuration
PhishGuard Live ships with full declarative deployment files:

### `render.yaml` Blueprint
```yaml
databases:
  - name: phishguard-db
    databaseName: phishguard
    user: phishguard_user
    plan: free
    region: oregon

services:
  - type: web
    name: phishguard-live
    runtime: python
    plan: free
    region: oregon
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app --bind 0.0.0.0:$PORT --workers 3 --timeout 120
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.9
      - key: FLASK_ENV
        value: production
      - key: SECRET_KEY
        generateValue: true
      - key: DATABASE_URL
        fromDatabase:
          name: phishguard-db
          property: connectionString
```

### `Procfile`
```
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 3 --timeout 120
```

### `runtime.txt`
```
python-3.11.9
```

---

## 3. Step-by-Step Render Deployment Workflow

### Step 1: Initialize and Push Git Repository
```bash
git init
git add .
git commit -m "feat: complete PhishGuard Live level 5 cybersecurity platform"
git branch -M main
git remote add origin https://github.com/Thabrez28/phishguard-live.git
git push -u origin main
```

### Step 2: Create Blueprint on Render
1. Open your browser and navigate to [https://dashboard.render.com/blueprints](https://dashboard.render.com/blueprints).
2. Click **New Blueprint Instance**.
3. Select your connected repository: `Thabrez28/phishguard-live`.
4. Render will inspect `render.yaml` and display:
   - Database: `phishguard-db` (PostgreSQL)
   - Web Service: `phishguard-live` (Python Web Service)
5. Click **Apply**.

### Step 3: Automated Provisioning & Verification
1. Render provisions the PostgreSQL database first and assigns a secure `DATABASE_URL`.
2. Render then builds the Python environment (`pip install -r requirements.txt`).
3. Render starts Gunicorn, binding to the dynamic `$PORT`.
4. The application automatically adapts `postgres://` to `postgresql://` in `config.py` and creates all required tables via `db.create_all()`.
5. The default admin account is automatically seeded if the database is brand new.

---

## 4. Automatic Database URL Adaptation
Render provides PostgreSQL connection strings with the prefix `postgres://`. However, SQLAlchemy 1.4+ and 2.0+ require `postgresql://`.

PhishGuard Live handles this automatically in `config.py`:
```python
_raw_db_url = os.environ.get("DATABASE_URL")
if _raw_db_url and _raw_db_url.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URI = _raw_db_url.replace("postgres://", "postgresql://", 1)
```
No manual intervention or code changes are required!

---

## 5. Live Production Verification Checklist
Once Render reports `Deploy Live`:
1. Verify Health Check:
   ```bash
   curl -I https://YOUR-APP.onrender.com/api/health
   # Must return HTTP 200 OK with {"status": "healthy", "database": "connected"}
   ```
2. Test Login:
   - Visit `https://YOUR-APP.onrender.com/login`
   - Log in with `admin` / `Admin@PhishGuard2026!`
3. Test Scanner:
   - Scan a safe URL: `https://python.org`
   - Scan a phishing URL: `http://paypal.com.verify-billing-update.xyz/login/secure`
4. Test External CLI Agent:
   ```bash
   export PHISHGUARD_API_URL="https://YOUR-APP.onrender.com"
   python agent/phishguard_agent.py "http://test-threat.top/login"
   ```
