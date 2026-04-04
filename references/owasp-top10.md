# OWASP Top 10 — Vulnerability Detection Patterns by Language

## Table of Contents
1. [A01:2021 — Broken Access Control](#a01)
2. [A02:2021 — Cryptographic Failures](#a02)
3. [A03:2021 — Injection](#a03)
4. [A04:2021 — Insecure Design](#a04)
5. [A05:2021 — Security Misconfiguration](#a05)
6. [A06:2021 — Vulnerable and Outdated Components](#a06)
7. [A07:2021 — Identification and Authentication Failures](#a07)
8. [A08:2021 — Software and Data Integrity Failures](#a08)
9. [A09:2021 — Security Logging and Monitoring Failures](#a09)
10. [A10:2021 — Server-Side Request Forgery (SSRF)](#a10)

---

<a name="a01"></a>
## A01:2021 — Broken Access Control

The most critical web application security risk. Occurs when users can act outside their intended permissions.

### Detection Patterns

**Missing Authorization Checks**
```
# Python/Django — views without @login_required or permission decorators
Grep: pattern="def (get|post|put|patch|delete)\(self" (then verify decorator presence)

# Node.js/Express — routes without auth middleware
Grep: pattern="router\.(get|post|put|delete)\(" (then check middleware chain)

# Java/Spring — endpoints without @PreAuthorize or @Secured
Grep: pattern="@(GetMapping|PostMapping|PutMapping|DeleteMapping)" (then check class/method annotations)

# PHP/Laravel — routes without middleware('auth')
Grep: pattern="Route::(get|post|put|delete)" (then check middleware)
```

**Insecure Direct Object References (IDOR)**
```
# Any language — user-supplied ID used directly to fetch resources
Grep: pattern="(params\[.id.\]|params\.id|request\.params\.id|getParameter\(.id.\))"
# Verify: is there an ownership check after fetching the resource?
```

**Privilege Escalation**
```
# Look for role checks that can be bypassed
Grep: pattern="(role|is_admin|isAdmin|user_type|userType|permission)"
# Verify: are these checks server-side? Can the client set these values?

# Look for admin endpoints accessible without proper checks
Grep: pattern="(\/admin|\/manage|\/dashboard|\/internal)"
```

**Path Traversal in Access Control**
```
# URL path used directly to determine resource access
Grep: pattern="(request\.path|req\.url|request\.getRequestURI)"
# Verify: is path normalized before comparison?
```

### What to Look For
- Routes/endpoints without authentication middleware
- Resources fetched by user-supplied ID without ownership verification
- Client-side role checks (can be modified by attacker)
- Missing function-level access control on admin operations
- CORS allowing credential requests from untrusted origins

---

<a name="a02"></a>
## A02:2021 — Cryptographic Failures

Previously "Sensitive Data Exposure." Focuses on failures related to cryptography that lead to data exposure.

### Detection Patterns

**Weak Algorithms**
```
# MD5 for passwords/security (broken)
Grep: pattern="(md5|MD5|hashlib\.md5|MessageDigest.*MD5|md5\()"

# SHA1 for security purposes (deprecated)
Grep: pattern="(sha1|SHA1|hashlib\.sha1|MessageDigest.*SHA-1)"

# DES/3DES encryption (broken)
Grep: pattern="(DES|3DES|TripleDES|DESede)"

# ECB mode (deterministic, leaks patterns)
Grep: pattern="(ECB|\.MODE_ECB|AES/ECB)"

# Hardcoded encryption keys
Grep: pattern="(key\s*=\s*[\"'][^\"']+[\"']|secret\s*=\s*[\"'][^\"']+[\"']|iv\s*=\s*[\"'][^\"']+[\"'])"
```

**Insufficient Password Hashing**
```
# Plain text passwords
Grep: pattern="password\s*=\s*(request|req|params)"
# Verify: is the password hashed before storage?

# Weak hashing without salt
Grep: pattern="(sha256|sha512)\((.*password|.*pass)"
# These need bcrypt/scrypt/argon2 instead

# Proper hashing (should be present)
Grep: pattern="(bcrypt|scrypt|argon2|pbkdf2|PBKDF2)"
```

**Data in Transit**
```
# HTTP URLs (should be HTTPS)
Grep: pattern="http://((?!localhost|127\.0\.0\.1|0\.0\.0\.0).)*"

# Disabled SSL verification
Grep: pattern="(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED.*0|InsecureSkipVerify.*true|CURLOPT_SSL_VERIFYPEER.*false)"
```

**Sensitive Data Exposure**
```
# Logging sensitive data
Grep: pattern="(log|print|console\.log|logger)\.(info|debug|warn|error).*\b(password|token|secret|key|credit.card|ssn|social.security)\b"

# Sensitive data in URLs (gets logged in server/proxy logs)
Grep: pattern="(password|token|secret|api.key)=.*(&|$)"
```

### What to Look For
- Passwords stored with reversible encryption instead of hashing
- Sensitive data transmitted over HTTP
- Weak random number generators for security purposes (`Math.random()`, `random.random()`)
- Cryptographic keys committed to source code
- Missing encryption for PII at rest

---

<a name="a03"></a>
## A03:2021 — Injection

Occurs when untrusted data is sent to an interpreter as part of a command or query.

### SQL Injection Patterns

**Python**
```python
# VULNERABLE — string formatting in queries
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# SAFE — parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**JavaScript/Node.js**
```javascript
// VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${userId}`)
db.query("SELECT * FROM users WHERE id = " + userId)

// SAFE
db.query("SELECT * FROM users WHERE id = $1", [userId])
```

**Java**
```java
// VULNERABLE
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// SAFE
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
```

**PHP**
```php
// VULNERABLE
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// SAFE
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $_GET['id']);
```

**Detection Grep Patterns**
```
# String concatenation/interpolation in SQL
Grep: pattern="(execute|query|rawQuery)\s*\(\s*(f[\"']|[\"'].*\+|[\"'].*\$\{|[\"'].*%s[\"']\s*%)"

# ORM raw queries (still injectable)
Grep: pattern="(\.raw\(|\.extra\(|Sequelize\.literal|knex\.raw|ActiveRecord.*find_by_sql)"
```

### XSS Patterns

```
# Direct rendering of user input (no escaping)
Grep: pattern="(innerHTML|outerHTML|document\.write|\.html\(|dangerouslySetInnerHTML|v-html|{!!.*!!}|\|safe|\|raw|<%=.*%>|Markup\()"

# Template engines without auto-escaping
Grep: pattern="(render_template_string|Template\(|Jinja2.*autoescape.*False|mark_safe)"
```

### Command Injection

```
# Shell execution with user input
Grep: pattern="(os\.system|subprocess\.(call|run|Popen).*shell\s*=\s*True|exec\(|eval\(|child_process\.exec|Runtime\.getRuntime\(\)\.exec|system\(|passthru\(|shell_exec\(|popen\()"

# Backtick execution
Grep: pattern="`.*\$.*`"
```

### What to Look For
- Any place where user input touches a query, command, or interpreter
- ORMs used with raw query methods
- Template rendering without auto-escaping
- `eval()` or equivalent in any language with user-influenced input
- LDAP, XPath, NoSQL queries with string concatenation

---

<a name="a04"></a>
## A04:2021 — Insecure Design

Design-level flaws that can't be fixed by implementation alone. Requires threat modeling.

### Detection Patterns

```
# Missing rate limiting on sensitive operations
Grep: pattern="(login|authenticate|reset.password|verify|otp|mfa)"
# Verify: is there rate limiting middleware/decorator?

# Missing account lockout
Grep: pattern="(failed.login|login.attempt|invalid.password)"
# Verify: is there a lockout mechanism after N failures?

# Race conditions in financial/critical operations
Grep: pattern="(balance|credit|debit|transfer|inventory|stock|quantity)"
# Verify: are these operations atomic/transactional?
```

### What to Look For
- No rate limiting on authentication endpoints
- No account lockout after failed attempts
- Missing CAPTCHA on public forms
- Race conditions in state-changing operations
- No transaction isolation for financial operations
- Missing input length limits
- No timeout on sensitive sessions

---

<a name="a05"></a>
## A05:2021 — Security Misconfiguration

Improperly configured security settings, defaults left unchanged, verbose errors.

### Detection Patterns

```
# Debug mode in production
Grep: pattern="(DEBUG\s*=\s*True|debug:\s*true|NODE_ENV.*development|FLASK_ENV.*development|RAILS_ENV.*development)"

# Default credentials
Grep: pattern="(password.*admin|password.*123|password.*default|password.*test|root:root|admin:admin)"

# Verbose error pages
Grep: pattern="(SHOW_ERRORS|display_errors|full_error_reports|detailed.errors|stacktrace.*true)"

# Directory listing enabled
Grep: pattern="(autoindex\s+on|Options.*Indexes|directory.browsing.*true|listings.*true)"

# Unnecessary features enabled
Grep: pattern="(TRACE|OPTIONS|CONNECT|enable_trace|allow_trace)"

# Default secret keys
Grep: pattern="(SECRET_KEY\s*=\s*[\"']change.me|sk-test-|pk-test-|REPLACE_ME|TODO.*secret|CHANGEME)"
```

### What to Look For
- Default configurations never changed
- Unnecessary features, ports, services enabled
- Error handling revealing stack traces to users
- Cloud storage with public access
- Missing security headers
- Outdated server software versions exposed in headers

---

<a name="a06"></a>
## A06:2021 — Vulnerable and Outdated Components

Using components with known vulnerabilities.

### Detection Patterns

```
# Check dependency files exist
Glob: pattern="**/{package.json,requirements.txt,Pipfile,Pipfile.lock,poetry.lock,Gemfile,Gemfile.lock,pom.xml,build.gradle,go.mod,go.sum,Cargo.toml,Cargo.lock,composer.json,composer.lock,*.csproj,packages.config}"

# Pinned vs unpinned versions
Grep: pattern="(>=|~=|~>|^|\*)" glob="**/requirements*.txt"
Grep: pattern="(\"\^|\"\~|\">=|\"\\*)" glob="**/package.json"
```

Use `scripts/dependency_checker.py` for automated CVE lookup.

### What to Look For
- Dependencies with known CVEs (use dependency_checker.py)
- Unpinned dependency versions (supply chain risk)
- Abandoned/unmaintained libraries
- Dependencies pulled from untrusted sources
- Lock files not committed to version control

---

<a name="a07"></a>
## A07:2021 — Identification and Authentication Failures

Weaknesses in authentication and session management.

### Detection Patterns

```
# Weak password policies
Grep: pattern="(min.?length|minlength|password.?len|MIN_PASSWORD)"
# Verify: minimum length >= 8, complexity requirements present

# Session management issues
Grep: pattern="(session|cookie|Set-Cookie|express-session|flask.session)"
# Verify: secure flags, rotation on auth, timeout configured

# Credential storage
Grep: pattern="(password|passwd|pwd).*=.*(request|req\.|params|input|argv)"
# Trace to verify hashing before storage

# JWT issues
Grep: pattern="(jwt\.sign|jwt\.verify|jose\.|pyjwt|jsonwebtoken)"
# Verify: algorithm specified, expiration set, secret is strong

# Missing MFA
Grep: pattern="(two.factor|2fa|mfa|totp|otp)"
# If absent in auth-critical app, flag as finding
```

### What to Look For
- Passwords accepted without minimum complexity
- Session IDs in URLs
- Sessions that don't expire or rotate
- "Remember me" tokens that are predictable
- Password reset tokens that don't expire
- Credentials transmitted without encryption

---

<a name="a08"></a>
## A08:2021 — Software and Data Integrity Failures

Code and infrastructure that doesn't protect against integrity violations.

### Detection Patterns

```
# Deserialization of untrusted data
Grep: pattern="(pickle\.loads|yaml\.load\((?!.*Loader)|unserialize\(|ObjectInputStream|JSON\.parse.*eval|readObject\(|Marshal\.load|fromJson.*Object)"

# Missing integrity checks on downloads/updates
Grep: pattern="(curl|wget|fetch|request\.get|urllib).*\.(sh|exe|zip|tar|pkg|deb|rpm)"
# Verify: is there a checksum/signature verification after download?

# Insecure CI/CD
Grep: pattern="(npm install|pip install|gem install|go get).*--no-verify"
Grep: pattern="(actions/checkout@master|uses:.*@master)" glob="**/.github/**"
```

### What to Look For
- Deserialization of data from untrusted sources
- CI/CD pipelines without integrity verification
- Auto-update mechanisms without signature verification
- Unpinned GitHub Actions (using `@master` instead of SHA)
- `eval()` on data from external sources

---

<a name="a09"></a>
## A09:2021 — Security Logging and Monitoring Failures

Insufficient logging, detection, monitoring, and active response.

### Detection Patterns

```
# Check for logging presence
Grep: pattern="(import logging|require.*winston|require.*bunyan|log4j|NLog|Serilog|logger)"

# Check what's logged
Grep: pattern="(log\.(info|warn|error|critical)|logger\.(info|warn|error)|console\.(log|error|warn))"

# Security events that should be logged
# Authentication attempts (success AND failure)
# Authorization failures
# Input validation failures
# Server-side errors
# Access to sensitive data
```

### What to Look For
- Authentication events not logged
- Authorization failures not logged
- No alerting mechanism for critical security events
- Logs stored without integrity protection
- Insufficient log retention
- Sensitive data in logs (passwords, tokens, PII)

---

<a name="a10"></a>
## A10:2021 — Server-Side Request Forgery (SSRF)

Application fetches a remote resource without validating the user-supplied URL.

### Detection Patterns

```
# URL fetch from user input
Grep: pattern="(requests\.get|urllib\.request\.urlopen|fetch\(|http\.get|axios\.(get|post)|HttpClient|curl_exec|file_get_contents).*\b(url|uri|href|link|src|target|redirect|callback|webhook)\b"

# URL validation (should be present near URL fetch)
Grep: pattern="(urlparse|URL\(|new URL|parse_url|filter_var.*FILTER_VALIDATE_URL)"

# Cloud metadata endpoints (critical SSRF targets)
Grep: pattern="(169\.254\.169\.254|metadata\.google|metadata\.azure|100\.100\.100\.200)"
```

### What to Look For
- User-supplied URLs fetched server-side without validation
- URL allowlist bypass (IP encoding, DNS rebinding, redirects)
- Internal service access through SSRF (cloud metadata, internal APIs)
- File protocol access (`file:///etc/passwd`)
- Missing network segmentation allowing SSRF to reach internal services
