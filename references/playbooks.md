# Security Remediation Playbooks

## Table of Contents
1. [SQL Injection Remediation](#pb-sqli)
2. [XSS Remediation](#pb-xss)
3. [Authentication Hardening](#pb-auth)
4. [API Security Hardening](#pb-api)
5. [Secrets Rotation Emergency](#pb-secrets)
6. [Dependency Vulnerability Response](#pb-deps)
7. [Container Security Hardening](#pb-container)
8. [CI/CD Pipeline Security](#pb-cicd)
9. [Incident Response Playbook](#pb-incident)
10. [Security Monitoring Setup](#pb-monitoring)

Each playbook follows this structure:
- **Objective** — What this playbook fixes
- **Severity** — Urgency level
- **Prerequisites** — What you need before starting
- **Steps** — Numbered action items with code
- **Verification** — How to confirm the fix works
- **Prevention** — How to prevent recurrence

---

<a name="pb-sqli"></a>
## 1. SQL Injection Remediation

**Objective:** Eliminate all SQL injection vectors in the codebase
**Severity:** CRITICAL — fix immediately
**Time estimate:** 1-4 hours per injection point

### Prerequisites
- Identify all injection points (use `static_analyzer.py --severity critical`)
- Have test environment with the same database schema
- Database backup before making changes

### Steps

**Step 1: Inventory all raw SQL queries**
```bash
# Find all potential injection points:
python scripts/static_analyzer.py --target . --severity critical --output /tmp/sqli-findings.json
# Review findings tagged with CWE-89
```

**Step 2: Convert to parameterized queries**

| Language | Before (Vulnerable) | After (Safe) |
|----------|-------------------|--------------|
| Python | `cursor.execute(f"SELECT * FROM users WHERE id = {uid}")` | `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` |
| Node.js | `` db.query(`SELECT * FROM users WHERE id = ${uid}`) `` | `db.query("SELECT * FROM users WHERE id = $1", [uid])` |
| Java | `stmt.executeQuery("SELECT * FROM users WHERE id = " + uid)` | `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, uid);` |
| PHP | `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id)` | `$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $id);` |
| Go | `db.Query("SELECT * FROM users WHERE id = " + uid)` | `db.Query("SELECT * FROM users WHERE id = $1", uid)` |
| C# | `cmd.CommandText = "SELECT * FROM users WHERE id = " + uid` | `cmd.CommandText = "SELECT * FROM users WHERE id = @uid"; cmd.Parameters.AddWithValue("@uid", uid);` |

**Step 3: Handle dynamic query parts (column names, ORDER BY)**
```python
# Column names cannot be parameterized — use allowlists:
ALLOWED_SORT_COLUMNS = {"name", "email", "created_at", "updated_at"}

def get_sorted_users(sort_by: str, order: str = "ASC"):
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"Invalid sort column: {sort_by}")
    if order.upper() not in ("ASC", "DESC"):
        raise ValueError(f"Invalid sort order: {order}")
    query = f"SELECT * FROM users ORDER BY {sort_by} {order}"
    cursor.execute(query)
```

**Step 4: Audit ORM usage**
```python
# Even ORMs can be vulnerable when using raw methods:
# Django
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])  # Safe
User.objects.extra(where=["name = '%s'" % name])                  # VULNERABLE!

# SQLAlchemy
session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})  # Safe
session.execute(f"SELECT * FROM users WHERE name = '{name}'")                     # VULNERABLE!
```

### Verification
```bash
# 1. Run static analyzer again — should show 0 SQL injection findings:
python scripts/static_analyzer.py --target . --severity critical | grep "CWE-89"

# 2. Run application test suite to verify queries still work
# 3. Manual test with injection payloads:
#    Input: ' OR '1'='1' --
#    Expected: error or no results (NOT all results)
```

### Prevention
- Add pre-commit hook with `static_analyzer.py` to block new injection patterns
- Use ORM exclusively for queries (avoid raw SQL)
- Code review checklist: verify parameterized queries in every PR with DB interaction
- Add CI/CD security gate: `report_generator.py --check-threshold critical`

---

<a name="pb-xss"></a>
## 2. XSS Remediation

**Objective:** Eliminate cross-site scripting vulnerabilities
**Severity:** HIGH — fix within 7 days

### Steps

**Step 1: Enable auto-escaping globally**
```python
# Django — already enabled by default, verify:
TEMPLATES = [{'OPTIONS': {'autoescape': True}}]  # default

# Flask/Jinja2 — enabled by default, verify:
app = Flask(__name__)  # Jinja2 auto-escaping is on by default for .html

# Express/EJS — configure:
app.set('view engine', 'ejs');  # EJS auto-escapes by default with <%= %>
```

**Step 2: Find and fix all escape-bypass patterns**
```bash
# Search for dangerous output methods:
# React: dangerouslySetInnerHTML
# Angular: [innerHTML], bypassSecurityTrust*
# Vue: v-html
# Django: |safe, mark_safe(), Markup()
# EJS: <%- %> (unescaped)
# Pug: != (unescaped)
```

**Step 3: For each escape bypass, either remove or sanitize**
```javascript
// If you MUST render HTML, sanitize it:
import DOMPurify from 'dompurify';

// Before (vulnerable):
element.innerHTML = userContent;

// After (safe):
element.innerHTML = DOMPurify.sanitize(userContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href']
});
```

**Step 4: Implement Content Security Policy**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
```

### Verification
- Input `<script>alert('XSS')</script>` in every user input field
- Check that it's rendered as text, not executed
- Verify CSP blocks inline scripts in browser console

---

<a name="pb-auth"></a>
## 3. Authentication Hardening

**Objective:** Secure all authentication flows
**Severity:** CRITICAL

### Steps

**Step 1: Password storage**
```python
# Use bcrypt with cost factor >= 12:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Or argon2 (preferred for new applications):
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
```

**Step 2: Rate limiting**
```python
# Django:
# pip install django-ratelimit
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    pass

# Express:
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Try again in 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.post('/api/auth/login', loginLimiter, loginHandler);
```

**Step 3: Session management**
```python
# Regenerate session on login:
request.session.cycle_key()  # Django
session.regenerate()         # Flask

# Set session timeout:
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Invalidate all sessions on password change:
from django.contrib.auth import update_session_auth_hash
update_session_auth_hash(request, user)
```

**Step 4: JWT security (if using tokens)**
```python
import jwt
from datetime import datetime, timedelta

# Signing:
token = jwt.encode({
    "sub": user.id,
    "exp": datetime.utcnow() + timedelta(hours=1),
    "iat": datetime.utcnow(),
    "iss": "myapp",
    "aud": "myapp-api",
}, PRIVATE_KEY, algorithm="RS256")

# Verification — ALWAYS specify algorithm:
payload = jwt.decode(token, PUBLIC_KEY,
    algorithms=["RS256"],
    options={"require": ["exp", "iss", "sub", "aud"]},
    issuer="myapp",
    audience="myapp-api",
)
```

**Step 5: MFA implementation**
```python
# TOTP with pyotp:
import pyotp

# Setup:
secret = pyotp.random_base32()  # Store securely per user
totp = pyotp.TOTP(secret)
provisioning_uri = totp.provisioning_uri(user.email, issuer_name="MyApp")

# Verification:
def verify_mfa(user, code):
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):  # Allow 30s window
        user.mfa_failed_attempts += 1
        if user.mfa_failed_attempts >= 5:
            user.lock_account()
        raise AuthError("Invalid MFA code")
    user.mfa_failed_attempts = 0
    # Invalidate used code (prevent reuse):
    cache.set(f"mfa_used:{user.id}:{code}", True, timeout=60)
```

### Verification Checklist
- [ ] Test login with wrong password → error, no info leak
- [ ] Test 10+ failed logins → rate limited/locked
- [ ] Test session after password change → old sessions invalid
- [ ] Test JWT with `alg: none` → rejected
- [ ] Test JWT with expired token → rejected
- [ ] Test MFA with reused code → rejected
- [ ] Test MFA brute force → locked after 5 attempts

---

<a name="pb-api"></a>
## 4. API Security Hardening

**Objective:** Secure all API endpoints
**Severity:** HIGH

### Steps

**Step 1: Input validation on every endpoint**
```python
# Use schema validation (e.g., Pydantic, marshmallow, Joi, Zod):
from pydantic import BaseModel, Field, EmailStr

class CreateUserRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    age: int = Field(ge=0, le=150)
    # role field NOT included — prevent mass assignment
```

**Step 2: Response filtering**
```python
# Never return the full database model:
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    # NOT included: password_hash, internal_id, is_admin, etc.

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = db.get_user(user_id)
    return UserResponse.from_orm(user)  # Only allowed fields
```

**Step 3: Authorization on every endpoint**
```python
# Object-level authorization:
@app.get("/orders/{order_id}")
async def get_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = db.get_order(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return order
```

**Step 4: Rate limiting per endpoint type**
```
Auth endpoints:     5 requests/minute
Write endpoints:    30 requests/minute
Read endpoints:     100 requests/minute
Search endpoints:   10 requests/minute
Export endpoints:   2 requests/minute
```

---

<a name="pb-secrets"></a>
## 5. Secrets Rotation Emergency

**Objective:** Respond to exposed/compromised secrets
**Severity:** CRITICAL — execute within 1 hour

### Steps

**Step 1: Identify exposure scope**
```bash
# What was exposed? Where? When?
# Check: git history, logs, error pages, public repos, paste sites
git log --all --full-history -S "SECRET_VALUE" -- '*.py' '*.js' '*.env'
```

**Step 2: Rotate immediately**
```bash
# Database passwords:
ALTER USER app_user WITH PASSWORD 'NEW_STRONG_PASSWORD';

# API keys:
# Revoke in provider dashboard and generate new key

# JWT secrets:
# Generate new: python -c "import secrets; print(secrets.token_hex(32))"
# Deploy new secret → all existing tokens are automatically invalidated

# AWS keys:
aws iam create-access-key --user-name app-user
aws iam delete-access-key --user-name app-user --access-key-id OLD_KEY_ID
```

**Step 3: Remove from git history** (if committed)
```bash
# Use git-filter-repo (preferred over filter-branch):
pip install git-filter-repo
git filter-repo --invert-paths --path .env
# Force push to all branches
# Notify all team members to re-clone
```

**Step 4: Prevent recurrence**
```bash
# Add to .gitignore:
echo ".env" >> .gitignore
echo "*.pem" >> .gitignore
echo "*.key" >> .gitignore

# Install pre-commit hook:
pip install detect-secrets
detect-secrets scan > .secrets.baseline
# Add to .pre-commit-config.yaml
```

---

<a name="pb-deps"></a>
## 6. Dependency Vulnerability Response

**Objective:** Remediate vulnerable dependencies
**Severity:** Varies by CVE

### Steps

**Step 1: Scan and prioritize**
```bash
python scripts/dependency_checker.py --target . --format markdown --output deps-audit.md
```

**Step 2: Update by priority**
```bash
# Critical/High — update immediately:
npm update lodash         # or: npm install lodash@4.17.21
pip install --upgrade django>=4.2.11

# Medium — update in current sprint:
# Group compatible updates together

# Low — update in maintenance cycle
```

**Step 3: Test after updating**
```bash
# Run full test suite:
npm test
pytest
# Run security scan again to verify:
python scripts/dependency_checker.py --target .
```

**Step 4: Automate ongoing monitoring**
```yaml
# GitHub Dependabot:
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

<a name="pb-container"></a>
## 7. Container Security Hardening

**Objective:** Secure Docker/Kubernetes deployment
**Severity:** HIGH

### Dockerfile Hardening Steps

```dockerfile
# Step 1: Use minimal base image with specific version
FROM node:20-alpine AS builder

# Step 2: Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

# Step 3: Install dependencies separately (cache layer)
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Step 4: Copy application code
COPY --chown=appuser:appuser . .

# Step 5: Switch to non-root user
USER appuser

# Step 6: Use read-only filesystem
# (set in docker-compose or kubernetes)

# Step 7: Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q --spider http://localhost:3000/health || exit 1

# Step 8: Minimal exposed ports
EXPOSE 3000

# Step 9: Exec form CMD (proper signal handling)
CMD ["node", "server.js"]
```

---

<a name="pb-cicd"></a>
## 8. CI/CD Pipeline Security

**Objective:** Secure the build and deploy pipeline
**Severity:** HIGH

### GitHub Actions Security Steps

```yaml
name: Secure Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read  # Step 1: Minimal permissions

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      # Step 2: Pin actions to SHA (not tags)
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      # Step 3: Security scanning before build
      - name: Static Analysis
        run: python scripts/static_analyzer.py --target . --output results/static.json

      - name: Dependency Check
        run: python scripts/dependency_checker.py --target . --output results/deps.json

      - name: Config Audit
        run: python scripts/config_auditor.py --target . --output results/config.json

      # Step 4: Security gate — fail on critical vulnerabilities
      - name: Security Gate
        run: python scripts/report_generator.py --input results/ --check-threshold critical

      # Step 5: Generate and archive report
      - name: Generate Report
        if: always()
        run: python scripts/report_generator.py --input results/ --format markdown --output results/report.md

      - name: Archive Security Report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4
        with:
          name: security-report
          path: results/
```

---

<a name="pb-incident"></a>
## 9. Incident Response Playbook

**Objective:** Structured response to security incidents
**Severity:** CRITICAL

### Phase 1: Detect & Triage (0-30 minutes)
1. Confirm the incident is real (not false positive)
2. Classify severity: data breach, unauthorized access, malware, DoS
3. Identify affected systems and data
4. Notify incident response team

### Phase 2: Contain (30-60 minutes)
1. Isolate affected systems (network segmentation)
2. Block attacker IP/accounts
3. Revoke compromised credentials
4. Preserve evidence (logs, memory dumps, disk images)

### Phase 3: Eradicate (1-24 hours)
1. Identify root cause and attack vector
2. Remove attacker access (backdoors, persistence)
3. Patch the vulnerability that was exploited
4. Scan for similar vulnerabilities in other systems

### Phase 4: Recover (24-72 hours)
1. Restore systems from clean backups
2. Re-deploy with patched code
3. Monitor for re-compromise
4. Gradually restore services

### Phase 5: Post-Incident (1-2 weeks)
1. Write incident report (timeline, impact, root cause)
2. Conduct blameless post-mortem
3. Update security controls to prevent recurrence
4. Review and update this playbook

---

<a name="pb-monitoring"></a>
## 10. Security Monitoring Setup

**Objective:** Establish ongoing security monitoring
**Severity:** MEDIUM (preventive)

### What to Monitor

```python
# Security events that MUST be logged:
SECURITY_EVENTS = [
    "login_success",
    "login_failure",
    "login_failure_locked",      # Account locked
    "password_change",
    "password_reset_request",
    "mfa_failure",
    "authorization_failure",     # 403 responses
    "rate_limit_exceeded",
    "input_validation_failure",  # Suspicious input
    "session_created",
    "session_destroyed",
    "admin_action",              # Any admin operation
    "data_export",               # Bulk data access
    "api_key_created",
    "api_key_revoked",
    "privilege_escalation",      # Role change
    "suspicious_user_agent",     # Known attack tools
]
```

### Alert Thresholds
```
# Alert immediately:
- 5+ failed logins for same account in 5 minutes
- Any login from new country/IP range
- Admin account creation
- Bulk data export
- SQL error patterns in logs
- Server error spike (5xx > 10/minute)

# Alert within 1 hour:
- 50+ failed logins from same IP
- Unusual API usage patterns
- New admin users created
- Dependency vulnerability detected (critical)

# Daily digest:
- Authentication statistics
- Rate limiting triggers
- New security findings from automated scans
- Dependency update availability
```
