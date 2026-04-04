#!/usr/bin/env python3
"""
Web Application Scanner (Black-Box) — Performs live HTTP reconnaissance and
vulnerability testing against a target URL. Discovers endpoints, analyzes
security headers, tests for common vulnerabilities, and crawls for attack surface.

Uses only Python standard library (urllib/http) — no external dependencies required.

Usage:
    python web_scanner.py --url <target-url> [--depth <crawl-depth>] [--output <file>] [--format json|markdown]
    python web_scanner.py --url https://example.com --depth 2 --output /tmp/scan.json
    python web_scanner.py --url http://localhost:3000 --format markdown --output report.md

Modes:
    --recon-only     Only perform reconnaissance (no active testing)
    --headers-only   Only analyze HTTP headers and TLS
    --full           Full scan: recon + headers + active tests (default)
"""

import argparse
import json
import os
import re
import ssl
import sys
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Optional


# ─── Constants ───

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/.git/config",
    "/wp-admin/", "/wp-login.php", "/admin", "/admin/", "/login", "/api",
    "/api/v1", "/api/v2", "/graphql", "/graphiql", "/playground",
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui/",
    "/debug", "/trace", "/actuator", "/actuator/health", "/actuator/env",
    "/server-status", "/server-info", "/.well-known/openid-configuration",
    "/phpinfo.php", "/info.php", "/test.php", "/.htaccess", "/web.config",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/elmah.axd",
    "/.DS_Store", "/backup.sql", "/dump.sql", "/database.sql",
    "/config.json", "/config.yaml", "/config.yml", "/settings.json",
    "/package.json", "/composer.json", "/.dockerenv",
    "/health", "/healthcheck", "/status", "/metrics", "/prometheus",
    "/_debug", "/__debug__", "/console", "/shell",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True, "severity": "high",
        "description": "Missing HSTS — vulnerable to SSL stripping attacks",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "required": True, "severity": "high",
        "description": "Missing CSP — no protection against XSS and data injection",
        "fix": "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Content-Type-Options": {
        "required": True, "severity": "medium",
        "description": "Missing X-Content-Type-Options — MIME sniffing possible",
        "fix": "Add header: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "required": True, "severity": "medium",
        "description": "Missing X-Frame-Options — clickjacking possible",
        "fix": "Add header: X-Frame-Options: DENY",
    },
    "Referrer-Policy": {
        "required": True, "severity": "low",
        "description": "Missing Referrer-Policy — referrer data may leak",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "required": False, "severity": "low",
        "description": "Missing Permissions-Policy — browser features unrestricted",
        "fix": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "required": False, "severity": "info",
        "description": "X-XSS-Protection header present — deprecated, CSP is preferred",
        "fix": "Set to 0 if CSP is present, or remove entirely",
    },
}

INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
]


# ─── HTML Parser for Link/Form Discovery ───

class LinkFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.scripts = []
        self.inputs = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            self.links.append(attrs_dict["href"])
        elif tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })
        elif tag == "input":
            self.inputs.append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
            })
        elif tag == "script" and "src" in attrs_dict:
            self.scripts.append(attrs_dict["src"])
        elif tag == "link" and attrs_dict.get("rel") == "stylesheet":
            pass  # skip CSS
        elif tag in ("img", "iframe", "embed", "object") and "src" in attrs_dict:
            self.links.append(attrs_dict["src"])

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ─── HTTP Utilities ───

def create_opener():
    """Create urllib opener with cookie support and custom headers."""
    cookie_jar = CookieJar()
    handlers = [
        urllib.request.HTTPCookieProcessor(cookie_jar),
        urllib.request.HTTPRedirectHandler(),
    ]

    # Create SSL context that works but logs issues
    ctx = ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))

    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener, cookie_jar


def fetch_url(opener, url, method="GET", data=None, headers=None, timeout=15):
    """Fetch a URL and return response data."""
    result = {
        "url": url, "status": 0, "headers": {}, "body": "",
        "redirect_url": None, "error": None, "response_time_ms": 0,
        "content_type": "", "content_length": 0,
    }

    try:
        if data and isinstance(data, str):
            data = data.encode("utf-8")
        elif data and isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        start = time.time()
        response = opener.open(req, timeout=timeout)
        elapsed = (time.time() - start) * 1000

        result["status"] = response.getcode()
        result["headers"] = dict(response.headers)
        result["redirect_url"] = response.geturl() if response.geturl() != url else None
        result["response_time_ms"] = round(elapsed, 1)
        result["content_type"] = response.headers.get("Content-Type", "")
        result["content_length"] = int(response.headers.get("Content-Length", 0))

        try:
            body = response.read(500000)  # Max 500KB
            charset = "utf-8"
            ct = result["content_type"]
            if "charset=" in ct:
                charset = ct.split("charset=")[-1].split(";")[0].strip()
            result["body"] = body.decode(charset, errors="replace")
        except Exception:
            result["body"] = ""

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = dict(e.headers) if e.headers else {}
        result["error"] = str(e)
        try:
            result["body"] = e.read(50000).decode("utf-8", errors="replace")
        except Exception:
            pass
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Reconnaissance ───

def check_tls(url):
    """Check TLS/SSL configuration."""
    findings = []
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme == "http":
        findings.append({
            "id": "BB-TLS-001", "name": "No HTTPS", "severity": "high",
            "category": "Transport Security", "cwe": "CWE-319",
            "description": "Site uses HTTP — all data transmitted in cleartext",
            "evidence": f"URL scheme: {parsed.scheme}",
            "fix": "Enable HTTPS with a valid TLS certificate",
        })
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                # Check protocol version
                if protocol in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "id": "BB-TLS-002", "name": f"Weak TLS version: {protocol}", "severity": "high",
                        "category": "Transport Security", "cwe": "CWE-326",
                        "description": f"Server supports {protocol} which is deprecated and vulnerable",
                        "evidence": f"Negotiated protocol: {protocol}",
                        "fix": "Configure server to only support TLSv1.2 and TLSv1.3",
                    })

                # Check certificate expiry
                if cert:
                    not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    days_left = (not_after - time.time()) / 86400
                    if days_left < 0:
                        findings.append({
                            "id": "BB-TLS-003", "name": "Expired TLS certificate", "severity": "critical",
                            "category": "Transport Security", "cwe": "CWE-295",
                            "description": "TLS certificate has expired",
                            "evidence": f"Expires: {cert.get('notAfter', 'unknown')}, Days: {int(days_left)}",
                            "fix": "Renew the TLS certificate immediately",
                        })
                    elif days_left < 30:
                        findings.append({
                            "id": "BB-TLS-004", "name": "TLS certificate expiring soon", "severity": "medium",
                            "category": "Transport Security", "cwe": "CWE-295",
                            "description": f"Certificate expires in {int(days_left)} days",
                            "evidence": f"Expires: {cert.get('notAfter', 'unknown')}",
                            "fix": "Renew the TLS certificate before expiry",
                        })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "id": "BB-TLS-005", "name": "Invalid TLS certificate", "severity": "high",
            "category": "Transport Security", "cwe": "CWE-295",
            "description": "TLS certificate verification failed",
            "evidence": str(e),
            "fix": "Install a valid certificate from a trusted CA",
        })
    except Exception:
        pass

    return findings


def analyze_headers(response_headers, url):
    """Analyze HTTP response headers for security issues."""
    findings = []
    headers_lower = {k.lower(): v for k, v in response_headers.items()}

    # Check required security headers
    for header, config in SECURITY_HEADERS.items():
        header_lower = header.lower()
        if header_lower not in headers_lower:
            if config["required"]:
                findings.append({
                    "id": f"BB-HDR-{header[:3].upper()}", "name": f"Missing: {header}",
                    "severity": config["severity"], "category": "HTTP Security Headers",
                    "cwe": "CWE-693", "description": config["description"],
                    "evidence": f"Header '{header}' not present in response",
                    "fix": config["fix"],
                })
        else:
            value = headers_lower[header_lower]
            # Check for weak CSP
            if header_lower == "content-security-policy":
                if "unsafe-inline" in value and "unsafe-eval" in value:
                    findings.append({
                        "id": "BB-HDR-CSP-WEAK", "name": "Weak CSP: unsafe-inline + unsafe-eval",
                        "severity": "high", "category": "HTTP Security Headers", "cwe": "CWE-693",
                        "description": "CSP allows both unsafe-inline and unsafe-eval — XSS protection is minimal",
                        "evidence": f"CSP: {value[:200]}",
                        "fix": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP, use nonces or hashes instead",
                    })

    # Check for information leakage headers
    for header in INFO_LEAK_HEADERS:
        header_lower = header.lower()
        if header_lower in headers_lower:
            findings.append({
                "id": "BB-HDR-LEAK", "name": f"Information leak: {header}",
                "severity": "low", "category": "Information Disclosure", "cwe": "CWE-200",
                "description": f"Header '{header}' reveals technology information",
                "evidence": f"{header}: {headers_lower[header_lower]}",
                "fix": f"Remove or suppress the '{header}' header",
            })

    # Check CORS
    if "access-control-allow-origin" in headers_lower:
        cors_origin = headers_lower["access-control-allow-origin"]
        cors_creds = headers_lower.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*":
            if cors_creds == "true":
                findings.append({
                    "id": "BB-CORS-001", "name": "CORS: wildcard with credentials",
                    "severity": "critical", "category": "CORS Misconfiguration", "cwe": "CWE-942",
                    "description": "CORS allows all origins WITH credentials — any site can make authenticated requests",
                    "evidence": f"Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
                    "fix": "Never combine wildcard origin with credentials. Restrict to specific trusted origins.",
                })
            else:
                findings.append({
                    "id": "BB-CORS-002", "name": "CORS: wildcard origin",
                    "severity": "medium", "category": "CORS Misconfiguration", "cwe": "CWE-942",
                    "description": "CORS allows all origins — any website can read responses",
                    "evidence": f"Access-Control-Allow-Origin: *",
                    "fix": "Restrict to specific trusted origins",
                })

    # Check cookies
    set_cookies = []
    for key, val in response_headers.items():
        if key.lower() == "set-cookie":
            set_cookies.append(val)

    for cookie_str in set_cookies:
        cookie_lower = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0].strip()

        is_session = any(kw in cookie_name.lower() for kw in
                        ["session", "sess", "sid", "token", "auth", "jwt", "login", "user"])

        if is_session:
            if "httponly" not in cookie_lower:
                findings.append({
                    "id": "BB-COOKIE-001", "name": f"Cookie missing HttpOnly: {cookie_name}",
                    "severity": "high", "category": "Cookie Security", "cwe": "CWE-1004",
                    "description": "Session cookie accessible to JavaScript — XSS can steal it",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}",
                    "fix": f"Add HttpOnly flag to cookie '{cookie_name}'",
                })
            if "secure" not in cookie_lower and url.startswith("https"):
                findings.append({
                    "id": "BB-COOKIE-002", "name": f"Cookie missing Secure: {cookie_name}",
                    "severity": "high", "category": "Cookie Security", "cwe": "CWE-614",
                    "description": "Session cookie can be sent over HTTP — interception possible",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}",
                    "fix": f"Add Secure flag to cookie '{cookie_name}'",
                })
            if "samesite" not in cookie_lower:
                findings.append({
                    "id": "BB-COOKIE-003", "name": f"Cookie missing SameSite: {cookie_name}",
                    "severity": "medium", "category": "Cookie Security", "cwe": "CWE-1275",
                    "description": "Cookie vulnerable to CSRF attacks without SameSite attribute",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}",
                    "fix": f"Add SameSite=Strict or SameSite=Lax to cookie '{cookie_name}'",
                })

    return findings


def discover_paths(opener, base_url):
    """Probe common paths for sensitive files and endpoints."""
    findings = []
    discovered = []

    for path in COMMON_PATHS:
        url = urllib.parse.urljoin(base_url, path)
        resp = fetch_url(opener, url, timeout=8)

        if resp["status"] in (200, 301, 302, 403):
            entry = {
                "path": path, "status": resp["status"],
                "content_type": resp.get("content_type", ""),
                "size": len(resp.get("body", "")),
            }
            discovered.append(entry)

            # Flag sensitive discoveries
            if resp["status"] == 200:
                if path in ("/.env", "/.git/HEAD", "/.git/config"):
                    findings.append({
                        "id": "BB-DISC-001", "name": f"Sensitive file exposed: {path}",
                        "severity": "critical", "category": "Information Disclosure", "cwe": "CWE-538",
                        "description": f"Sensitive file accessible at {path}",
                        "evidence": f"HTTP {resp['status']} — {resp.get('body', '')[:200]}",
                        "fix": f"Block access to {path} in web server configuration",
                    })
                elif path in ("/phpinfo.php", "/info.php", "/test.php"):
                    findings.append({
                        "id": "BB-DISC-002", "name": f"Debug file exposed: {path}",
                        "severity": "high", "category": "Information Disclosure", "cwe": "CWE-200",
                        "description": f"Debug/info file accessible — reveals server configuration",
                        "evidence": f"HTTP {resp['status']} at {url}",
                        "fix": f"Remove {path} from production server",
                    })
                elif any(kw in path for kw in ["/actuator", "/debug", "/__debug__", "/console", "/shell"]):
                    findings.append({
                        "id": "BB-DISC-003", "name": f"Debug endpoint exposed: {path}",
                        "severity": "high", "category": "Information Disclosure", "cwe": "CWE-489",
                        "description": f"Debug/management endpoint accessible in production",
                        "evidence": f"HTTP {resp['status']} at {url}",
                        "fix": f"Disable or restrict access to {path} in production",
                    })
                elif any(kw in path for kw in ["/swagger", "/openapi", "/api-docs", "/graphiql", "/playground"]):
                    findings.append({
                        "id": "BB-DISC-004", "name": f"API documentation exposed: {path}",
                        "severity": "medium", "category": "Information Disclosure", "cwe": "CWE-200",
                        "description": f"API documentation publicly accessible — reveals API structure",
                        "evidence": f"HTTP {resp['status']} at {url}",
                        "fix": f"Restrict {path} to authenticated users or internal networks",
                    })
                elif any(kw in path for kw in [".sql", "backup", "dump", "database"]):
                    findings.append({
                        "id": "BB-DISC-005", "name": f"Database backup exposed: {path}",
                        "severity": "critical", "category": "Information Disclosure", "cwe": "CWE-530",
                        "description": f"Database dump/backup file publicly accessible",
                        "evidence": f"HTTP {resp['status']} at {url}",
                        "fix": f"Remove {path} from web-accessible directory immediately",
                    })

    return findings, discovered


def crawl_page(opener, url, base_url, depth=1, visited=None):
    """Crawl a page and extract links, forms, and scripts."""
    if visited is None:
        visited = set()
    if url in visited or depth < 0:
        return [], [], []
    visited.add(url)

    resp = fetch_url(opener, url, timeout=10)
    if resp["error"] or not resp["body"]:
        return [], [], []

    ct = resp.get("content_type", "")
    if "text/html" not in ct and "application/xhtml" not in ct:
        return [], [], []

    parser = LinkFormParser()
    try:
        parser.feed(resp["body"])
    except Exception:
        pass

    # Resolve relative links
    all_links = []
    parsed_base = urllib.parse.urlparse(base_url)
    for link in parser.links:
        try:
            resolved = urllib.parse.urljoin(url, link)
            parsed_link = urllib.parse.urlparse(resolved)
            # Only follow same-origin links
            if parsed_link.hostname == parsed_base.hostname:
                clean = urllib.parse.urlunparse(parsed_link._replace(fragment=""))
                if clean not in visited:
                    all_links.append(clean)
        except Exception:
            continue

    forms = parser.forms
    for form in forms:
        form["page_url"] = url
        if form["action"]:
            form["action"] = urllib.parse.urljoin(url, form["action"])
        else:
            form["action"] = url

    scripts = []
    for src in parser.scripts:
        scripts.append(urllib.parse.urljoin(url, src))

    # Recurse into discovered links
    if depth > 0:
        for link in all_links[:30]:  # Limit to avoid excessive crawling
            sub_links, sub_forms, sub_scripts = crawl_page(
                opener, link, base_url, depth - 1, visited
            )
            all_links.extend(sub_links)
            forms.extend(sub_forms)
            scripts.extend(sub_scripts)

    return list(set(all_links)), forms, scripts


# ─── Active Testing ───

SQLI_PROBES = ["'", "' OR '1'='1", "1' AND '1'='2", "1; SELECT 1--", "' UNION SELECT NULL--"]
XSS_PROBES = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'-alert(1)-'"]
CMDI_PROBES = ["; echo pentest_marker", "| echo pentest_marker", "`echo pentest_marker`"]
SSTI_PROBES = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
TRAVERSAL_PROBES = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd"]

SQLI_INDICATORS = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "ORA-", "unterminated",
                   "quoted string", "near \"'\"", "unexpected", "SQLSTATE"]
XSS_REFLECTION_MARKER = "pentest_xss_marker_49283"


def test_parameter_injection(opener, url, param_name, param_value, method="GET"):
    """Test a single parameter for injection vulnerabilities."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    base = urllib.parse.urlunparse(parsed._replace(query=""))

    # SQL Injection
    for probe in SQLI_PROBES:
        test_val = param_value + probe if param_value else probe
        if method == "GET":
            test_url = f"{base}?{urllib.parse.urlencode({param_name: test_val})}"
            resp = fetch_url(opener, test_url, timeout=10)
        else:
            resp = fetch_url(opener, base, method="POST",
                           data={param_name: test_val},
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           timeout=10)

        body_lower = resp.get("body", "").lower()
        if resp["status"] == 500 or any(ind in body_lower for ind in SQLI_INDICATORS):
            findings.append({
                "id": "BB-SQLI-001", "name": f"Potential SQL Injection: {param_name}",
                "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
                "description": f"Parameter '{param_name}' may be vulnerable to SQL injection",
                "evidence": f"Payload: {probe} | Status: {resp['status']} | "
                           f"Error indicators found in response",
                "fix": "Use parameterized queries. Never concatenate user input into SQL.",
                "endpoint": url, "parameter": param_name, "method": method,
                "payload": probe,
            })
            break  # One finding per param is enough

    # XSS (Reflected)
    xss_marker = XSS_REFLECTION_MARKER
    xss_payloads = [
        f"<img src=x onerror=alert('{xss_marker}')>",
        f"\"><script>{xss_marker}</script>",
        f"'-{xss_marker}-'",
    ]
    for payload in xss_payloads:
        if method == "GET":
            test_url = f"{base}?{urllib.parse.urlencode({param_name: payload})}"
            resp = fetch_url(opener, test_url, timeout=10)
        else:
            resp = fetch_url(opener, base, method="POST",
                           data={param_name: payload},
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           timeout=10)

        if xss_marker in resp.get("body", ""):
            # Check if it's reflected without encoding
            body = resp.get("body", "")
            if payload in body or f"onerror=alert('{xss_marker}')" in body:
                findings.append({
                    "id": "BB-XSS-001", "name": f"Reflected XSS: {param_name}",
                    "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
                    "description": f"Parameter '{param_name}' reflects input without encoding — XSS possible",
                    "evidence": f"Payload reflected in response body without HTML encoding",
                    "fix": "Encode all user input before rendering in HTML. Use Content-Security-Policy.",
                    "endpoint": url, "parameter": param_name, "method": method,
                    "payload": payload,
                })
                break

    # Path Traversal
    for probe in TRAVERSAL_PROBES:
        if method == "GET":
            test_url = f"{base}?{urllib.parse.urlencode({param_name: probe})}"
            resp = fetch_url(opener, test_url, timeout=10)
        else:
            resp = fetch_url(opener, base, method="POST",
                           data={param_name: probe},
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           timeout=10)

        body = resp.get("body", "")
        if "root:" in body or "[fonts]" in body or "boot loader" in body.lower():
            findings.append({
                "id": "BB-TRAV-001", "name": f"Path Traversal: {param_name}",
                "severity": "critical", "category": "A01:2021-Access", "cwe": "CWE-22",
                "description": f"Parameter '{param_name}' allows file system traversal",
                "evidence": f"Payload: {probe} | System file content found in response",
                "fix": "Validate and normalize file paths. Use allowlists for permitted files.",
                "endpoint": url, "parameter": param_name, "method": method,
                "payload": probe,
            })
            break

    # SSTI
    for probe in SSTI_PROBES:
        if method == "GET":
            test_url = f"{base}?{urllib.parse.urlencode({param_name: probe})}"
            resp = fetch_url(opener, test_url, timeout=10)
        else:
            resp = fetch_url(opener, base, method="POST",
                           data={param_name: probe},
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           timeout=10)

        if "49" in resp.get("body", "") and probe in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
            findings.append({
                "id": "BB-SSTI-001", "name": f"Server-Side Template Injection: {param_name}",
                "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-1336",
                "description": f"Parameter '{param_name}' is evaluated as a template expression",
                "evidence": f"Payload: {probe} | '49' found in response (7*7=49)",
                "fix": "Never place user input in template strings. Use template variables instead.",
                "endpoint": url, "parameter": param_name, "method": method,
                "payload": probe,
            })
            break

    return findings


def test_forms(opener, forms):
    """Test discovered HTML forms for vulnerabilities."""
    findings = []
    tested_actions = set()

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET")
        if action in tested_actions:
            continue
        tested_actions.add(action)

        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if not name:
                continue
            inp_type = inp.get("type", "text").lower()
            if inp_type in ("hidden", "submit", "button", "image", "reset"):
                continue

            param_findings = test_parameter_injection(
                opener, action, name, inp.get("value", ""), method
            )
            findings.extend(param_findings)

        # Check for CSRF protection
        input_names = [i.get("name", "").lower() for i in form.get("inputs", [])]
        has_csrf = any(kw in name for name in input_names
                      for kw in ["csrf", "token", "_token", "xsrf", "authenticity"])
        if method == "POST" and not has_csrf:
            findings.append({
                "id": "BB-CSRF-001", "name": f"Missing CSRF token in form",
                "severity": "medium", "category": "A01:2021-Access", "cwe": "CWE-352",
                "description": f"POST form at {action} has no CSRF token — vulnerable to CSRF",
                "evidence": f"Form action: {action}, inputs: {input_names}",
                "fix": "Add a CSRF token to all state-changing forms",
                "endpoint": action,
            })

    return findings


def test_url_params(opener, urls):
    """Test URL query parameters for injection."""
    findings = []
    tested = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue

        for param_name, values in params.items():
            key = f"{parsed.path}:{param_name}"
            if key in tested:
                continue
            tested.add(key)

            param_findings = test_parameter_injection(
                opener, url, param_name, values[0] if values else "", "GET"
            )
            findings.extend(param_findings)

    return findings


# ─── Main Scanner ───

def run_scan(url, depth=1, mode="full"):
    """Execute full black-box security scan."""
    print(f"[*] Target: {url}", file=sys.stderr)
    print(f"[*] Mode: {mode} | Crawl depth: {depth}", file=sys.stderr)

    all_findings = []
    scan_data = {
        "target": url, "mode": mode, "depth": depth,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tls": {}, "headers": {}, "paths_discovered": [],
        "links_found": 0, "forms_found": 0, "scripts_found": 0,
    }

    opener, cookie_jar = create_opener()

    # Phase 1: TLS check
    print("[*] Phase 1: TLS/SSL analysis...", file=sys.stderr)
    tls_findings = check_tls(url)
    all_findings.extend(tls_findings)
    scan_data["tls"] = {"findings": len(tls_findings)}

    # Phase 2: Initial request + header analysis
    print("[*] Phase 2: HTTP headers analysis...", file=sys.stderr)
    initial = fetch_url(opener, url)
    if initial["error"] and initial["status"] == 0:
        print(f"[!] Cannot reach target: {initial['error']}", file=sys.stderr)
        return {"findings": all_findings, "scan_data": scan_data, "error": initial["error"]}

    header_findings = analyze_headers(initial["headers"], url)
    all_findings.extend(header_findings)
    scan_data["headers"] = dict(initial["headers"])

    if mode == "headers-only":
        return {"findings": all_findings, "scan_data": scan_data}

    # Phase 3: Path discovery
    print("[*] Phase 3: Path discovery (probing common paths)...", file=sys.stderr)
    path_findings, discovered = discover_paths(opener, url)
    all_findings.extend(path_findings)
    scan_data["paths_discovered"] = discovered

    if mode == "recon-only":
        return {"findings": all_findings, "scan_data": scan_data}

    # Phase 4: Crawl and discover
    print(f"[*] Phase 4: Crawling (depth={depth})...", file=sys.stderr)
    links, forms, scripts = crawl_page(opener, url, url, depth=depth)
    scan_data["links_found"] = len(links)
    scan_data["forms_found"] = len(forms)
    scan_data["scripts_found"] = len(scripts)
    print(f"    Found {len(links)} links, {len(forms)} forms, {len(scripts)} scripts", file=sys.stderr)

    # Phase 5: Active testing
    print("[*] Phase 5: Active vulnerability testing...", file=sys.stderr)

    # Test forms
    print(f"    Testing {len(forms)} forms...", file=sys.stderr)
    form_findings = test_forms(opener, forms)
    all_findings.extend(form_findings)

    # Test URL parameters
    urls_with_params = [l for l in links if "?" in l]
    print(f"    Testing {len(urls_with_params)} parameterized URLs...", file=sys.stderr)
    url_findings = test_url_params(opener, urls_with_params)
    all_findings.extend(url_findings)

    # Test initial URL parameters too
    if "?" in url:
        init_findings = test_url_params(opener, [url])
        all_findings.extend(init_findings)

    print(f"[*] Scan complete: {len(all_findings)} findings", file=sys.stderr)
    return {"findings": all_findings, "scan_data": scan_data}


# ─── Output Formatting ───

def format_markdown(results, url):
    findings = results.get("findings", [])
    scan = results.get("scan_data", {})

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    risk = min(100, sev_counts["critical"]*25 + sev_counts["high"]*15 + sev_counts["medium"]*5 + sev_counts["low"])

    lines = [
        "# Black-Box Security Scan Report",
        f"**Target:** `{url}`",
        f"**Date:** {scan.get('timestamp', 'N/A')}",
        f"**Mode:** {scan.get('mode', 'full')}",
        f"**Risk Score:** {risk}/100",
        "",
        "## Summary",
        f"| Severity | Count |", "|-|-|",
        f"| Critical | {sev_counts['critical']} |",
        f"| High | {sev_counts['high']} |",
        f"| Medium | {sev_counts['medium']} |",
        f"| Low | {sev_counts['low']} |",
        f"| Info | {sev_counts['info']} |",
        "",
        f"**Links discovered:** {scan.get('links_found', 0)}",
        f"**Forms discovered:** {scan.get('forms_found', 0)}",
        f"**Paths probed:** {len(scan.get('paths_discovered', []))}",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4))

    for f in sorted_findings:
        sev = f.get("severity", "info").upper()
        lines.extend([
            f"### [{sev}] {f.get('name', 'Unknown')}",
            f"- **Category:** {f.get('category', 'N/A')}",
            f"- **CWE:** {f.get('cwe', 'N/A')}",
        ])
        if f.get("endpoint"):
            lines.append(f"- **Endpoint:** `{f['endpoint']}`")
        if f.get("parameter"):
            lines.append(f"- **Parameter:** `{f['parameter']}`")
        if f.get("payload"):
            lines.append(f"- **Payload:** `{f['payload']}`")
        lines.extend([
            f"- **Evidence:** {f.get('evidence', 'N/A')}",
            f"- **Description:** {f.get('description', 'N/A')}",
            f"- **Fix:** {f.get('fix', 'N/A')}",
            "",
        ])

    if scan.get("paths_discovered"):
        lines.extend(["## Discovered Paths", "", "| Path | Status | Content-Type |", "|-|-|-|"])
        for p in scan["paths_discovered"]:
            lines.append(f"| {p['path']} | {p['status']} | {p.get('content_type', '')[:40]} |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Web Application Scanner (Black-Box) — live HTTP security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com --output scan.json
  %(prog)s --url http://localhost:3000 --depth 2 --format markdown --output report.md
  %(prog)s --url https://target.com --recon-only
        """
    )
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--recon-only", action="store_true", help="Only recon, no active testing")
    parser.add_argument("--headers-only", action="store_true", help="Only analyze headers/TLS")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")

    args = parser.parse_args()

    mode = "full"
    if args.recon_only:
        mode = "recon-only"
    elif args.headers_only:
        mode = "headers-only"

    results = run_scan(args.url, depth=args.depth, mode=mode)

    if args.format == "markdown":
        output = format_markdown(results, args.url)
    else:
        output = json.dumps(results, indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\nReport written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
