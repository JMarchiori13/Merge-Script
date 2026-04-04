# Security Hardening Reference

## Table of Contents
1. [Web Server Hardening](#webserver)
2. [Database Hardening](#database)
3. [Application Hardening](#application)
4. [Container & Docker Hardening](#container)
5. [Cloud & Infrastructure Hardening](#cloud)
6. [Dependency & Supply Chain Security](#supply-chain)
7. [Secrets Management](#secrets)
8. [Security Headers Quick Reference](#headers)

---

<a name="webserver"></a>
## 1. Web Server Hardening

### Nginx
```nginx
# Hide server version
server_tokens off;

# Security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;

# Rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

# Disable unnecessary HTTP methods
if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|OPTIONS)$) {
    return 405;
}

# File upload limits
client_max_body_size 10M;
client_body_timeout 10s;
client_header_timeout 10s;
```

### Apache
```apache
# Hide server version
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Disable directory listing
Options -Indexes

# Disable server-side includes
Options -Includes

# Prevent .htaccess override in sensitive dirs
<Directory /var/www/html/uploads>
    AllowOverride None
    Options -ExecCGI
    RemoveHandler .php .phtml .php3 .php4 .php5
</Directory>
```

### Checklist
- [ ] Server version hidden from response headers
- [ ] TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1)
- [ ] Strong cipher suites only
- [ ] HSTS enabled with preload
- [ ] Directory listing disabled
- [ ] Unnecessary modules/features disabled
- [ ] Request rate limiting configured
- [ ] File upload size limits set
- [ ] Access logs enabled and rotated
- [ ] Error pages don't reveal server info

---

<a name="database"></a>
## 2. Database Hardening

### PostgreSQL
```sql
-- Use strong password hashing
-- In pg_hba.conf: use scram-sha-256 instead of md5
-- host all all 0.0.0.0/0 scram-sha-256

-- Restrict network access
-- In postgresql.conf:
-- listen_addresses = 'localhost'  (or specific IPs)

-- Enable SSL
-- ssl = on
-- ssl_cert_file = '/path/to/server.crt'
-- ssl_key_file = '/path/to/server.key'

-- Create application-specific users with minimal privileges
CREATE USER app_user WITH PASSWORD 'strong_password';
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_user;
-- NEVER use superuser for application connections

-- Enable logging
-- log_statement = 'ddl'  (or 'mod' for all modifications)
-- log_connections = on
-- log_disconnections = on

-- Row-level security for multi-tenant apps
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders
    USING (tenant_id = current_setting('app.current_tenant')::int);
```

### MySQL
```sql
-- Remove default test database and anonymous users
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
FLUSH PRIVILEGES;

-- Create application user with minimal privileges
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'localhost';

-- Disable local file loading (prevents LOAD DATA attacks)
-- In my.cnf: local-infile=0

-- Enable audit logging
-- Install audit plugin for MySQL Enterprise
```

### MongoDB
```javascript
// Enable authentication (disabled by default!)
// In mongod.conf:
// security:
//   authorization: enabled

// Create admin user
db.createUser({
  user: "admin",
  pwd: "strong_password",
  roles: [{ role: "userAdminAnyDatabase", db: "admin" }]
});

// Create application user with minimal privileges
db.createUser({
  user: "app_user",
  pwd: "strong_password",
  roles: [{ role: "readWrite", db: "app_db" }]
});

// Disable server-side JavaScript (prevents NoSQL injection escalation)
// In mongod.conf:
// security:
//   javascriptEnabled: false

// Bind to localhost only
// net:
//   bindIp: 127.0.0.1
```

### Database Checklist
- [ ] Default credentials changed
- [ ] Application uses dedicated user with minimal privileges
- [ ] Network access restricted (not exposed to internet)
- [ ] SSL/TLS enabled for connections
- [ ] Audit logging enabled
- [ ] Backups encrypted and tested
- [ ] No `SELECT *` — only fetch needed columns
- [ ] Connection pooling configured (prevent exhaustion)
- [ ] Query timeout configured

---

<a name="application"></a>
## 3. Application Hardening

### Node.js / Express
```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

// Security headers (covers most security headers at once)
app.use(helmet());

// CORS — be specific, never use wildcard with credentials
app.use(cors({
  origin: 'https://myapp.com',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
app.use('/api/auth/', rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                     // 10 attempts
  message: 'Too many login attempts'
}));

// Body parsing limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// Session security
app.use(session({
  secret: process.env.SESSION_SECRET,  // From environment, never hardcoded
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // HTTPS only
    httpOnly: true,     // No JS access
    sameSite: 'strict', // CSRF protection
    maxAge: 3600000     // 1 hour
  },
  store: new RedisStore({ client: redisClient })  // Not MemoryStore
}));

// Disable fingerprinting
app.disable('x-powered-by');
```

### Python / Django
```python
# settings.py

# Security settings
DEBUG = False
ALLOWED_HOSTS = ['myapp.com']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

# HTTPS
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookies
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Content Security
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = True  # deprecated but harmless

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Session
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_COOKIE_AGE = 3600  # 1 hour
```

### Python / Flask
```python
from flask_talisman import Talisman
from flask_limiter import Limiter

# Security headers via Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
})

# Rate limiting
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass

# Session configuration
app.config.update(
    SECRET_KEY=os.environ['FLASK_SECRET_KEY'],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=3600,
)
```

### Application Checklist
- [ ] Debug mode disabled in production
- [ ] Secret keys from environment variables (never hardcoded)
- [ ] Security headers configured (use helmet/talisman equivalent)
- [ ] CORS properly restricted
- [ ] Rate limiting on auth and expensive endpoints
- [ ] Input validation on all endpoints
- [ ] Error handling doesn't leak internals
- [ ] File uploads validated (type, size, name)
- [ ] Logging configured (no sensitive data in logs)
- [ ] Dependencies up to date

---

<a name="container"></a>
## 4. Container & Docker Hardening

### Dockerfile Best Practices
```dockerfile
# Use specific version, not :latest
FROM node:20-alpine

# Run as non-root
RUN addgroup -g 1001 appuser && adduser -u 1001 -G appuser -s /bin/sh -D appuser

# Copy only what's needed
COPY --chown=appuser:appuser package*.json ./
RUN npm ci --only=production

COPY --chown=appuser:appuser . .

# Drop all capabilities
USER appuser

# Don't expose unnecessary ports
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --spider http://localhost:3000/health || exit 1

# Use exec form (signals handled correctly)
CMD ["node", "server.js"]
```

### Docker Compose Security
```yaml
services:
  app:
    image: myapp:1.0
    read_only: true              # Read-only filesystem
    security_opt:
      - no-new-privileges:true   # Prevent privilege escalation
    cap_drop:
      - ALL                      # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE         # Add only what's needed
    tmpfs:
      - /tmp                     # Writable tmp in memory
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
    networks:
      - frontend
    # Don't mount Docker socket!
    # Don't use --privileged!

  db:
    image: postgres:16
    networks:
      - backend                  # DB not on frontend network
    volumes:
      - db-data:/var/lib/postgresql/data
```

### Container Checklist
- [ ] Base image is minimal and pinned to specific version
- [ ] Running as non-root user
- [ ] Read-only filesystem where possible
- [ ] No privileged mode
- [ ] Capabilities dropped (only add what's needed)
- [ ] Resource limits set (memory, CPU)
- [ ] Network segmentation (DB not exposed to frontend)
- [ ] Docker socket not mounted
- [ ] Secrets not in image (use runtime injection)
- [ ] Image scanning in CI/CD pipeline

---

<a name="cloud"></a>
## 5. Cloud & Infrastructure Hardening

### Common Misconfigurations

**AWS**
```
# S3 buckets
- Public access enabled (Block Public Access should be ON)
- Bucket policies allowing s3:GetObject to Principal: *
- Missing encryption (SSE-S3 or SSE-KMS should be enabled)

# IAM
- Root account used for daily operations
- Overly permissive policies (Action: *, Resource: *)
- Long-lived access keys (rotate every 90 days)
- No MFA on privileged accounts

# Security Groups
- 0.0.0.0/0 on SSH (port 22) or RDP (port 3389)
- All traffic allowed between security groups
- Outbound rules too permissive

# Lambda
- Overly permissive execution role
- Secrets in environment variables (use Secrets Manager)
- No VPC attachment for functions accessing internal resources
```

**General Cloud Checklist**
- [ ] Principle of least privilege for all IAM roles
- [ ] MFA enabled on all admin/root accounts
- [ ] Encryption at rest enabled for all storage
- [ ] Encryption in transit for all communication
- [ ] Network segmentation (VPCs, subnets, security groups)
- [ ] Audit logging enabled (CloudTrail, Cloud Audit Logs)
- [ ] No public access to databases or internal services
- [ ] Secrets managed through dedicated service (not env vars)
- [ ] Regular access reviews
- [ ] Backup strategy tested

---

<a name="supply-chain"></a>
## 6. Dependency & Supply Chain Security

### Package Manager Security

```
# Lock files must be committed
# npm: package-lock.json
# pip: requirements.txt with pinned versions, or Pipfile.lock
# Go: go.sum
# Ruby: Gemfile.lock
# Rust: Cargo.lock

# Use exact versions in production
# BAD:  "lodash": "^4.0.0"   (allows 4.x.x)
# GOOD: "lodash": "4.17.21"  (exact version)

# Verify package integrity
npm audit
pip-audit
bundle audit
cargo audit
```

### Supply Chain Checklist
- [ ] Lock files committed to version control
- [ ] Dependencies pinned to exact versions in production
- [ ] Automated vulnerability scanning in CI/CD
- [ ] No dependencies from untrusted registries
- [ ] GitHub Actions pinned to SHA (not tags)
- [ ] Code review for dependency additions
- [ ] Regular dependency updates (automated with Dependabot/Renovate)

---

<a name="secrets"></a>
## 7. Secrets Management

### What Should NEVER Be in Code
```
# API keys, passwords, tokens, certificates, private keys
Grep: pattern="(password|passwd|pwd|secret|token|apikey|api_key|private_key|credential|auth)\s*[:=]\s*[\"'][^\"']{8,}[\"']"

# AWS credentials
Grep: pattern="(AKIA[0-9A-Z]{16}|aws_secret_access_key|aws_access_key_id)"

# Private keys
Grep: pattern="-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"

# Connection strings with credentials
Grep: pattern="(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@"
```

### Secrets Management Best Practices
1. **Use environment variables** for simple deployments
2. **Use a secrets manager** for production (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
3. **Rotate secrets regularly** — especially after team changes
4. **Use `.gitignore`** to prevent `.env` files from being committed
5. **Scan git history** — a secret removed from code is still in git history

### Pre-commit Hook for Secret Detection
```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

---

<a name="headers"></a>
## 8. Security Headers Quick Reference

| Header | Recommended Value | Purpose |
|--------|-------------------|---------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'` | Prevents XSS, clickjacking, data injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Forces HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking (legacy, CSP preferred) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restricts browser features |
| `X-XSS-Protection` | `0` | Disabled (CSP is the modern solution) |
| `Cache-Control` | `no-store` (for sensitive pages) | Prevents caching of sensitive data |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates browsing context |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevents cross-origin resource loading |
