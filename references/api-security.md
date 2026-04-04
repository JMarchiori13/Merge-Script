# API Security Testing Reference

## Table of Contents
1. [JWT Security](#jwt)
2. [OAuth2 / OpenID Connect](#oauth)
3. [REST API Security](#rest)
4. [GraphQL Security](#graphql)
5. [Session Management](#session)
6. [Rate Limiting & DoS Prevention](#rate)
7. [API Authentication Patterns](#auth-patterns)

---

<a name="jwt"></a>
## 1. JWT Security

### Common Vulnerabilities

**Algorithm Confusion (Critical)**
The `alg` field in the JWT header tells the server which algorithm to use for verification. If the server doesn't enforce a specific algorithm, an attacker can:

1. **`none` algorithm**: Set `alg: "none"` and remove the signature
```json
// Header
{"alg": "none", "typ": "JWT"}
// Payload
{"sub": "admin", "role": "admin"}
// Signature: (empty)
```

2. **HS256/RS256 confusion**: If the server uses RS256 (asymmetric), change to HS256 (symmetric) and sign with the **public key** as the HMAC secret
```python
# Attack: sign with the public key using HS256
import jwt
public_key = open('public.pem').read()
token = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
```

**Detection Patterns**
```
# Check for algorithm enforcement
Grep: pattern="(algorithms\s*=|algorithm\s*[:=]|\.verify\()"
# Vulnerable: jwt.decode(token, key)  — no algorithm specified
# Safe: jwt.decode(token, key, algorithms=["RS256"])

# Check for 'none' algorithm acceptance
Grep: pattern="(none|None|NONE).*alg"

# Check for weak secrets
Grep: pattern="(jwt\.sign|jwt\.encode).*[\"'](secret|password|key|123|test|changeme)"
```

**Missing Expiration**
```
# Tokens without exp claim never expire
Grep: pattern="(jwt\.sign|jwt\.encode)"
# Verify: does the payload include 'exp'?
# Verify: does verification check 'exp'?
```

**Token Storage**
```
# JWT in localStorage (accessible to XSS)
Grep: pattern="localStorage\.(setItem|getItem).*token"

# Better: HttpOnly cookie (not accessible to JS)
```

### JWT Testing Checklist
- [ ] Algorithm is explicitly enforced (not read from token)
- [ ] `none` algorithm is rejected
- [ ] Tokens have reasonable expiration (exp claim)
- [ ] Tokens are invalidated on logout/password change
- [ ] Secret key is strong (>256 bits for HS256)
- [ ] Sensitive data is not stored in payload (it's base64, not encrypted)
- [ ] Token refresh mechanism exists for long sessions
- [ ] Audience (aud) and issuer (iss) claims are validated

### Remediation
```python
# Python (PyJWT)
import jwt

# SIGNING — always set expiration
token = jwt.encode(
    {"sub": user_id, "exp": datetime.utcnow() + timedelta(hours=1), "iss": "myapp"},
    PRIVATE_KEY,
    algorithm="RS256"
)

# VERIFICATION — always specify algorithm
payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"],  # Explicitly restrict to RS256
    options={"require": ["exp", "iss", "sub"]},
    issuer="myapp"
)
```

---

<a name="oauth"></a>
## 2. OAuth2 / OpenID Connect

### Common Vulnerabilities

**Authorization Code Flow Issues**
```
# Missing state parameter (CSRF in OAuth)
Grep: pattern="(authorize\?|authorization_endpoint)(?!.*state=)"

# Redirect URI validation
Grep: pattern="(redirect_uri|callback_url|return_url)"
# Verify: is it validated against a strict allowlist?
# Vulnerable patterns:
#   - Open redirect: redirect_uri=https://attacker.com
#   - Subdomain bypass: redirect_uri=https://evil.legit-app.com
#   - Path confusion: redirect_uri=https://legit-app.com/.attacker.com
```

**Token Handling**
```
# Access tokens in URL fragments or query params (logged by proxies)
Grep: pattern="(access_token|code)=.*[&?]"

# Implicit flow (deprecated — tokens exposed in URL)
Grep: pattern="response_type=token"

# Missing PKCE for public clients
Grep: pattern="(code_challenge|code_verifier)"
# If absent in SPA/mobile app, flag as finding
```

### OAuth Testing Checklist
- [ ] State parameter present and validated (CSRF protection)
- [ ] Redirect URI strictly validated (exact match, not prefix)
- [ ] PKCE used for public clients (SPAs, mobile apps)
- [ ] Authorization codes are single-use
- [ ] Tokens have minimal scope
- [ ] Refresh tokens are rotated on use
- [ ] Token revocation endpoint exists

---

<a name="rest"></a>
## 3. REST API Security

### Endpoint Discovery
```
# Find all route definitions
Grep: pattern="@(app|router)\.(get|post|put|patch|delete)\([\"'/]"
Grep: pattern="@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)"
Grep: pattern="Route::(get|post|put|patch|delete|any|match)"

# Find OpenAPI/Swagger definitions
Glob: pattern="**/{swagger,openapi}*.{json,yaml,yml}"
Grep: pattern="(swagger|openapi).*['\"]([23]\.[0-9])"
```

### Common API Vulnerabilities

**Mass Assignment / Over-posting**
```python
# VULNERABLE — accepts all fields from request
user = User(**request.json)
User.objects.create(**request.data)

# SAFE — explicit field allowlist
allowed = {'name', 'email'}
data = {k: v for k, v in request.json.items() if k in allowed}
user = User(**data)
```

**Broken Object-Level Authorization (BOLA/IDOR)**
```
# Pattern: resource accessed by user-supplied ID without ownership check
GET /api/users/123/orders    # Can user 456 access user 123's orders?
GET /api/invoices/INV-001    # Can any authenticated user access any invoice?
PUT /api/profiles/123        # Can user 456 modify user 123's profile?
```

**Excessive Data Exposure**
```
# API returns more fields than the client needs
# Check: does the API serialize the entire database model?
Grep: pattern="(serialize|to_json|to_dict|as_dict|toJSON)(?!.*exclude)"
# Verify: are sensitive fields (password_hash, internal_id, etc.) excluded?
```

**Missing Rate Limiting**
```
# Check for rate limiting middleware
Grep: pattern="(rateLimit|rate_limit|throttle|RateLimiter|@throttle)"

# Critical endpoints that MUST have rate limiting:
# - Login / authentication
# - Password reset
# - OTP / MFA verification
# - API key generation
# - File upload
# - Search / export (resource-intensive)
```

**Insecure HTTP Methods**
```
# Check if dangerous methods are allowed
# OPTIONS request should not reveal: TRACE, CONNECT
# PUT/DELETE should require authentication
Grep: pattern="(app\.use|router\.all|\*)"
# Check if wildcard method handlers exist
```

### REST API Testing Checklist
- [ ] Authentication required on all non-public endpoints
- [ ] Object-level authorization (users can only access their own resources)
- [ ] Function-level authorization (users can only access their role's functions)
- [ ] Input validation on all parameters (type, length, range, format)
- [ ] Rate limiting on sensitive endpoints
- [ ] Response filtering (no over-fetching of data)
- [ ] Pagination on list endpoints (prevent data dump)
- [ ] HTTPS enforced, HTTP redirects or blocks
- [ ] Proper error responses (no stack traces, internal paths)
- [ ] API versioning strategy in place

---

<a name="graphql"></a>
## 4. GraphQL Security

### Discovery
```
# Find GraphQL endpoints
Grep: pattern="(graphql|\/graphql|apolloServer|makeExecutableSchema|buildSchema)"
Glob: pattern="**/*.graphql"
Glob: pattern="**/*.gql"
Grep: pattern="(typeDefs|resolvers|schema)"
```

### Common Vulnerabilities

**Introspection Enabled in Production**
```graphql
# This query should NOT work in production:
{
  __schema {
    types { name fields { name type { name } } }
  }
}
```

**Denial of Service via Deep/Circular Queries**
```graphql
# Deeply nested query — can crash the server
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

**Batching Attacks**
```graphql
# Multiple operations in one request to bypass rate limiting
[
  { "query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }" }
]
```

**Authorization Bypass via Field Selection**
```graphql
# Normal query returns limited fields
{ user(id: 1) { name email } }

# But what if we request admin fields?
{ user(id: 1) { name email role passwordHash internalId } }
```

### GraphQL Testing Checklist
- [ ] Introspection disabled in production
- [ ] Query depth limiting implemented
- [ ] Query complexity analysis / cost limiting
- [ ] Batching limited or disabled
- [ ] Field-level authorization (not just type-level)
- [ ] Rate limiting per client/IP
- [ ] Input validation on all arguments
- [ ] No sensitive data in error messages

---

<a name="session"></a>
## 5. Session Management

### Detection Patterns
```
# Session configuration
Grep: pattern="(session|cookie).*\{" -A 10
Grep: pattern="(express-session|flask.session|django\.contrib\.sessions|Rack::Session)"

# Session ID generation
Grep: pattern="(session.?id|sessionId|JSESSIONID|PHPSESSID|connect\.sid)"

# Session storage
Grep: pattern="(MemoryStore|session\.memory|cookie-session|CookieStore)"
# MemoryStore = not suitable for production (memory leak, no persistence)
```

### Session Security Checklist
- [ ] Session IDs are random (>128 bits of entropy)
- [ ] Session IDs are not in URLs
- [ ] Session regenerated on authentication (prevent fixation)
- [ ] Session invalidated on logout (server-side)
- [ ] Session timeout configured (idle + absolute)
- [ ] Cookie flags: HttpOnly, Secure, SameSite
- [ ] Concurrent session limiting (optional but recommended)

---

<a name="rate"></a>
## 6. Rate Limiting & DoS Prevention

### What to Check
```
# Rate limiting middleware
Grep: pattern="(express-rate-limit|ratelimit|throttle|slowapi|django-ratelimit|rack-attack)"

# Resource-intensive operations without limits
Grep: pattern="(export|download|report|search|upload|batch|bulk)"
# Verify: are these rate-limited or paginated?

# Regular expressions vulnerable to ReDoS
Grep: pattern="(re\.compile|new RegExp|/.*\+.*\+.*/|/.*\*.*\*.*/"
# Look for: nested quantifiers like (a+)+ or (a|a)*b
```

### DoS Prevention Checklist
- [ ] Rate limiting on all public endpoints
- [ ] Request size limits configured
- [ ] Pagination on all list endpoints
- [ ] Timeout on all external calls
- [ ] Connection limits configured
- [ ] Regular expressions reviewed for ReDoS
- [ ] File upload size limits
- [ ] Query complexity limits (GraphQL/database)

---

<a name="auth-patterns"></a>
## 7. API Authentication Patterns

### Security Comparison

| Method | Security Level | Best For | Risks |
|--------|---------------|----------|-------|
| API Keys | Low | Server-to-server, internal | Keys in code/logs, no expiration |
| Bearer Tokens (JWT) | Medium | SPAs, mobile apps | Token theft via XSS, algorithm confusion |
| OAuth2 + PKCE | High | Third-party integration, SPAs | Complex implementation, redirect attacks |
| mTLS | Very High | Microservices, B2B | Certificate management overhead |
| Session Cookies | Medium | Traditional web apps | CSRF, session fixation |

### Common API Auth Mistakes
1. **API key in URL query parameter** — logged by proxies, browser history, server logs
2. **Bearer token in localStorage** — accessible to XSS attacks
3. **No token rotation** — compromised token works forever
4. **Same token for auth + refresh** — if stolen, attacker has permanent access
5. **Missing audience/scope validation** — token from service A works on service B
