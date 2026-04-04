#!/usr/bin/env python3
"""
Security Playbook Generator — Generates automated remediation playbooks from scan findings.
Each playbook provides step-by-step instructions, code fixes, and verification commands.

Usage:
    python playbook_generator.py --input <scan-results.json> [--output <file>] [--format json|markdown]
    python playbook_generator.py --input <results-dir/> --output playbook.md --format markdown

Examples:
    python playbook_generator.py --input /tmp/pentest-results/ --format markdown --output /tmp/playbook.md
    python playbook_generator.py --input static-results.json --output playbook.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─── Playbook Templates ───
# Each template is keyed by CWE or vulnerability pattern ID

PLAYBOOK_TEMPLATES = {
    "CWE-89": {
        "title": "SQL Injection Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "1-2 hours per injection point",
        "steps": [
            {
                "action": "Identify all injection points",
                "command": "python scripts/static_analyzer.py --target . --severity critical | grep CWE-89",
                "description": "List all SQL injection findings with file and line number",
            },
            {
                "action": "Convert to parameterized queries",
                "description": "Replace string concatenation/formatting with parameterized queries",
                "code_examples": {
                    "python": {
                        "before": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                        "after": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                    },
                    "javascript": {
                        "before": 'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
                        "after": 'db.query("SELECT * FROM users WHERE id = $1", [userId])',
                    },
                    "java": {
                        "before": 'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)',
                        "after": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
                    },
                    "php": {
                        "before": 'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"])',
                        "after": '$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->bind_param("s", $_GET["id"]);',
                    },
                },
            },
            {
                "action": "Handle dynamic column names",
                "description": "Use allowlists for any dynamic SQL parts that cannot be parameterized (column names, table names, ORDER BY)",
                "code_examples": {
                    "python": {
                        "before": 'query = f"SELECT * FROM users ORDER BY {sort_column}"',
                        "after": 'ALLOWED = {"name", "email", "created_at"}\nif sort_column not in ALLOWED:\n    raise ValueError("Invalid column")\nquery = f"SELECT * FROM users ORDER BY {sort_column}"',
                    },
                },
            },
            {
                "action": "Verify fix",
                "command": "python scripts/static_analyzer.py --target . --severity critical | grep CWE-89\n# Should return 0 findings",
                "description": "Re-run scanner to confirm all injection points are fixed",
            },
            {
                "action": "Add regression prevention",
                "description": "Add static analysis to CI/CD pipeline to catch future injection attempts",
                "command": "# Add to CI/CD:\npython scripts/report_generator.py --input results/ --check-threshold critical",
            },
        ],
    },

    "CWE-79": {
        "title": "Cross-Site Scripting (XSS) Remediation",
        "priority": "P1 — Fix within 7 days",
        "estimated_effort": "30 minutes - 2 hours per finding",
        "steps": [
            {
                "action": "Enable auto-escaping globally",
                "description": "Verify template engine auto-escaping is enabled",
                "code_examples": {
                    "python": {"before": "Jinja2(autoescape=False)", "after": "Jinja2(autoescape=True)  # Default"},
                    "javascript": {"before": "element.innerHTML = userInput", "after": "element.textContent = userInput"},
                },
            },
            {
                "action": "Fix dangerous render patterns",
                "description": "Replace innerHTML, dangerouslySetInnerHTML, v-html, |safe with safe alternatives",
                "command": "# Find all dangerous patterns:\ngrep -rn 'innerHTML\\|dangerouslySetInnerHTML\\|v-html\\|\\|safe\\|mark_safe\\|Markup(' --include='*.py' --include='*.js' --include='*.ts' --include='*.vue' --include='*.html' .",
            },
            {
                "action": "Sanitize where HTML rendering is required",
                "code_examples": {
                    "javascript": {
                        "before": "element.innerHTML = userContent;",
                        "after": "import DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userContent);",
                    },
                },
            },
            {
                "action": "Implement Content Security Policy",
                "description": "Add CSP header to prevent inline script execution",
                "code_examples": {
                    "nginx": {
                        "before": "# No CSP header",
                        "after": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';\" always;",
                    },
                },
            },
            {
                "action": "Verify fix",
                "description": "Test all input fields with XSS payloads",
                "command": "# Input: <script>alert('XSS')</script>\n# Expected: rendered as text, not executed\n# Check browser console for CSP violations",
            },
        ],
    },

    "CWE-78": {
        "title": "Command Injection Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "1-2 hours per injection point",
        "steps": [
            {
                "action": "Replace shell execution with safe alternatives",
                "code_examples": {
                    "python": {
                        "before": 'subprocess.run(f"convert {filename} output.png", shell=True)',
                        "after": 'subprocess.run(["convert", filename, "output.png"])  # No shell',
                    },
                    "javascript": {
                        "before": "child_process.exec('convert ' + filename + ' output.png')",
                        "after": "child_process.execFile('convert', [filename, 'output.png'])",
                    },
                },
            },
            {
                "action": "If shell is required, escape arguments",
                "code_examples": {
                    "python": {
                        "before": 'os.system(f"process {user_input}")',
                        "after": 'import shlex\nsubprocess.run(f"process {shlex.quote(user_input)}", shell=True)',
                    },
                },
            },
            {
                "action": "Prefer library APIs over CLI tools",
                "description": "When possible, use Python/Node libraries instead of shelling out to CLI tools",
            },
        ],
    },

    "CWE-798": {
        "title": "Hardcoded Credentials Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "30 minutes per secret + rotation time",
        "steps": [
            {
                "action": "Identify all hardcoded secrets",
                "command": "python scripts/static_analyzer.py --target . --severity critical | grep CWE-798\npython scripts/config_auditor.py --target . | grep 'secret\\|password\\|key\\|token'",
            },
            {
                "action": "Move secrets to environment variables",
                "code_examples": {
                    "python": {
                        "before": 'SECRET_KEY = "my-super-secret-key-12345"',
                        "after": 'import os\nSECRET_KEY = os.environ["SECRET_KEY"]',
                    },
                    "javascript": {
                        "before": 'const apiKey = "sk-1234567890abcdef"',
                        "after": 'const apiKey = process.env.API_KEY',
                    },
                },
            },
            {
                "action": "Rotate compromised secrets",
                "description": "Generate new secrets and revoke old ones. Old secrets in git history are compromised.",
                "command": "# Generate new secret:\npython -c \"import secrets; print(secrets.token_hex(32))\"",
            },
            {
                "action": "Remove from git history",
                "description": "If secrets were committed, they exist in git history even after removal from code",
                "command": "# Use git-filter-repo:\npip install git-filter-repo\ngit filter-repo --invert-paths --path .env",
            },
            {
                "action": "Prevent recurrence",
                "command": "# Add to .gitignore:\necho '.env' >> .gitignore\necho '*.pem' >> .gitignore\necho '*.key' >> .gitignore\n\n# Install pre-commit secret detection:\npip install detect-secrets\ndetect-secrets scan > .secrets.baseline",
            },
        ],
    },

    "CWE-502": {
        "title": "Insecure Deserialization Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "1-3 hours per deserialization point",
        "steps": [
            {
                "action": "Replace unsafe deserialization with safe alternatives",
                "code_examples": {
                    "python": {
                        "before": "data = pickle.loads(user_input)\ndata = yaml.load(user_input)",
                        "after": "data = json.loads(user_input)  # Safe alternative\ndata = yaml.safe_load(user_input)  # Safe YAML",
                    },
                    "java": {
                        "before": "ObjectInputStream ois = new ObjectInputStream(input);\nObject obj = ois.readObject();",
                        "after": "// Use Jackson JSON instead:\nObjectMapper mapper = new ObjectMapper();\nMyClass obj = mapper.readValue(input, MyClass.class);",
                    },
                    "php": {
                        "before": "$data = unserialize($user_input);",
                        "after": "$data = json_decode($user_input, true);",
                    },
                },
            },
            {
                "action": "If deserialization is required, add integrity verification",
                "code_examples": {
                    "python": {
                        "before": "data = pickle.loads(untrusted_data)",
                        "after": "import hmac\n# Verify HMAC before deserializing:\nexpected_mac = hmac.new(SECRET_KEY, serialized_data, 'sha256').hexdigest()\nif not hmac.compare_digest(received_mac, expected_mac):\n    raise ValueError('Integrity check failed')\ndata = pickle.loads(serialized_data)",
                    },
                },
            },
        ],
    },

    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF) Remediation",
        "priority": "P1 — Fix within 7 days",
        "estimated_effort": "2-4 hours",
        "steps": [
            {
                "action": "Implement URL validation",
                "code_examples": {
                    "python": {
                        "before": "response = requests.get(user_provided_url)",
                        "after": "import ipaddress\nfrom urllib.parse import urlparse\n\nALLOWED_SCHEMES = {'http', 'https'}\nBLOCKED_RANGES = [\n    ipaddress.ip_network('127.0.0.0/8'),\n    ipaddress.ip_network('10.0.0.0/8'),\n    ipaddress.ip_network('172.16.0.0/12'),\n    ipaddress.ip_network('192.168.0.0/16'),\n    ipaddress.ip_network('169.254.0.0/16'),\n]\n\ndef validate_url(url):\n    parsed = urlparse(url)\n    if parsed.scheme not in ALLOWED_SCHEMES:\n        raise ValueError('Invalid scheme')\n    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n    for net in BLOCKED_RANGES:\n        if ip in net:\n            raise ValueError('Internal network blocked')\n    return url\n\nresponse = requests.get(validate_url(user_provided_url))",
                    },
                },
            },
            {
                "action": "Use allowlist for known-good domains",
                "description": "If possible, restrict to specific trusted domains instead of blocking bad ones",
            },
            {
                "action": "Block cloud metadata endpoints",
                "description": "Ensure 169.254.169.254 and metadata.google.internal are blocked",
            },
        ],
    },

    "CWE-327": {
        "title": "Weak Cryptography Remediation",
        "priority": "P1 — Fix within 7 days",
        "estimated_effort": "1-2 hours",
        "steps": [
            {
                "action": "Replace weak hash algorithms",
                "code_examples": {
                    "python": {
                        "before": "hashlib.md5(password.encode()).hexdigest()\nhashlib.sha1(data).hexdigest()",
                        "after": "# For passwords — use bcrypt or argon2:\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\n# For data integrity — use SHA-256:\nimport hashlib\nhashed = hashlib.sha256(data).hexdigest()",
                    },
                },
            },
            {
                "action": "Use cryptographically secure random",
                "code_examples": {
                    "python": {"before": "import random\ntoken = random.randint(0, 999999)", "after": "import secrets\ntoken = secrets.token_hex(32)"},
                    "javascript": {"before": "const token = Math.random().toString(36)", "after": "const crypto = require('crypto');\nconst token = crypto.randomBytes(32).toString('hex');"},
                },
            },
        ],
    },

    "CWE-295": {
        "title": "SSL/TLS Verification Remediation",
        "priority": "P1 — Fix within 7 days",
        "estimated_effort": "30 minutes",
        "steps": [
            {
                "action": "Enable SSL verification",
                "code_examples": {
                    "python": {"before": "requests.get(url, verify=False)", "after": "requests.get(url, verify=True)  # Default, or specify CA bundle:\nrequests.get(url, verify='/path/to/ca-bundle.crt')"},
                    "javascript": {"before": "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'", "after": "// Remove this line entirely.\n// If using self-signed certs, configure the CA:\nconst https = require('https');\nconst agent = new https.Agent({ ca: fs.readFileSync('ca.pem') });"},
                },
            },
        ],
    },

    "CWE-611": {
        "title": "XXE (XML External Entity) Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "30 minutes per XML parser",
        "steps": [
            {
                "action": "Disable external entity processing",
                "code_examples": {
                    "python": {"before": "import xml.etree.ElementTree as ET\ntree = ET.parse(user_file)", "after": "import defusedxml.ElementTree as ET\ntree = ET.parse(user_file)  # Safe by default"},
                    "java": {"before": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();", "after": 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\ndbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);'},
                },
            },
        ],
    },

    "CWE-330": {
        "title": "Weak Random Number Generator Remediation",
        "priority": "P1 — Fix within 7 days",
        "estimated_effort": "30 minutes",
        "steps": [
            {
                "action": "Replace with cryptographic random",
                "code_examples": {
                    "python": {"before": "import random\ntoken = random.randint(100000, 999999)", "after": "import secrets\ntoken = secrets.randbelow(900000) + 100000"},
                    "javascript": {"before": "const id = Math.random().toString(36).substr(2)", "after": "const crypto = require('crypto');\nconst id = crypto.randomBytes(16).toString('hex');"},
                },
            },
        ],
    },

    "CWE-22": {
        "title": "Path Traversal Remediation",
        "priority": "P0 — Fix Immediately",
        "estimated_effort": "1 hour per file operation",
        "steps": [
            {
                "action": "Validate and normalize file paths",
                "code_examples": {
                    "python": {
                        "before": "filepath = os.path.join(UPLOAD_DIR, user_filename)\nwith open(filepath) as f: ...",
                        "after": "import os\n\ndef safe_path(base_dir, user_filename):\n    requested = os.path.realpath(os.path.join(base_dir, user_filename))\n    if not requested.startswith(os.path.realpath(base_dir)):\n        raise ValueError('Path traversal detected')\n    return requested\n\nfilepath = safe_path(UPLOAD_DIR, user_filename)\nwith open(filepath) as f: ...",
                    },
                },
            },
        ],
    },
}

# Map finding IDs/names to CWEs for playbook lookup
ID_TO_CWE = {
    "PY-INJ-001": "CWE-89", "JS-INJ-006": "CWE-89", "JV-INJ-001": "CWE-89", "PHP-INJ-001": "CWE-89", "GO-INJ-001": "CWE-89", "CS-INJ-001": "CWE-89", "RB-INJ-001": "CWE-89",
    "PY-INJ-002": "CWE-78", "PY-INJ-005": "CWE-78", "JS-INJ-005": "CWE-78", "JV-INJ-002": "CWE-78", "PHP-INJ-002": "CWE-78", "GO-INJ-002": "CWE-78", "CS-INJ-002": "CWE-78", "RB-INJ-002": "CWE-78",
    "PY-INJ-003": "CWE-78", "PY-INJ-004": "CWE-78", "JS-INJ-001": "CWE-78", "PHP-INJ-003": "CWE-78",
    "PY-XSS-001": "CWE-79", "JS-INJ-002": "CWE-79", "JS-INJ-003": "CWE-79", "JS-INJ-004": "CWE-79", "PHP-XSS-001": "CWE-79", "CS-XSS-001": "CWE-79", "RB-XSS-001": "CWE-79",
    "PY-DES-001": "CWE-502", "PY-DES-002": "CWE-502", "JV-DES-001": "CWE-502", "PHP-DES-001": "CWE-502", "CS-DES-001": "CWE-502", "RB-DES-001": "CWE-502",
    "PY-CRY-001": "CWE-327", "PY-CRY-002": "CWE-327", "JV-CRY-001": "CWE-327",
    "PY-CRY-003": "CWE-798", "JS-CRY-002": "CWE-798", "GEN-SEC-001": "CWE-798", "GEN-SEC-002": "CWE-798", "GEN-SEC-003": "CWE-798", "GEN-SEC-004": "CWE-798", "GEN-SEC-008": "CWE-798",
    "PY-CRY-004": "CWE-330", "JS-CRY-001": "CWE-330", "GO-CRY-001": "CWE-330",
    "PY-TLS-001": "CWE-295", "GO-TLS-001": "CWE-295",
    "PY-SSRF-001": "CWE-918",
    "PY-PATH-001": "CWE-22",
    "JV-XXE-001": "CWE-611",
    "PHP-FI-001": "CWE-22",
    "PY-INJ-006": "CWE-79",
}


def load_findings(input_path: str) -> list:
    """Load findings from a JSON file or directory."""
    findings = []
    path = Path(input_path)

    if path.is_dir():
        for json_file in path.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                findings.extend(data.get("findings", []))
            except (json.JSONDecodeError, IOError):
                continue
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings = data.get("findings", data if isinstance(data, list) else [])
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading {input_path}: {e}", file=sys.stderr)

    return findings


def generate_playbooks(findings: list) -> list:
    """Generate playbooks for all unique vulnerability types found."""
    # Collect unique CWEs from findings
    cwe_findings = {}
    for f in findings:
        cwe = f.get("cwe", "")
        if not cwe:
            # Try to look up by finding ID
            finding_id = f.get("id", "")
            cwe = ID_TO_CWE.get(finding_id, "")
        if not cwe:
            continue

        if cwe not in cwe_findings:
            cwe_findings[cwe] = []
        cwe_findings[cwe].append(f)

    playbooks = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for cwe, related_findings in sorted(cwe_findings.items(), key=lambda x: severity_order.get(x[1][0].get("severity", "info"), 4)):
        template = PLAYBOOK_TEMPLATES.get(cwe)
        if not template:
            continue

        playbook = {
            "cwe": cwe,
            "title": template["title"],
            "priority": template["priority"],
            "estimated_effort": template["estimated_effort"],
            "affected_locations": [
                {"file": f.get("file", "N/A"), "line": f.get("line", ""), "name": f.get("name", "")}
                for f in related_findings
            ],
            "finding_count": len(related_findings),
            "steps": template["steps"],
        }
        playbooks.append(playbook)

    return playbooks


def format_markdown(playbooks: list, findings_total: int, input_path: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# Security Remediation Playbook",
        "",
        f"**Generated:** {now}",
        f"**Source:** `{input_path}`",
        f"**Total findings:** {findings_total}",
        f"**Playbooks generated:** {len(playbooks)}",
        "",
        "---",
        "",
        "## Table of Contents",
        "",
    ]

    for i, pb in enumerate(playbooks, 1):
        lines.append(f"{i}. [{pb['title']}](#{pb['cwe'].lower()}) — {pb['priority']} ({pb['finding_count']} findings)")
    lines.extend(["", "---", ""])

    for pb in playbooks:
        lines.extend([
            f"<a name=\"{pb['cwe'].lower()}\"></a>",
            f"## {pb['title']}",
            "",
            f"**CWE:** {pb['cwe']}",
            f"**Priority:** {pb['priority']}",
            f"**Estimated Effort:** {pb['estimated_effort']}",
            f"**Affected Locations:** {pb['finding_count']}",
            "",
        ])

        # List affected files
        lines.append("### Affected Files")
        for loc in pb["affected_locations"][:20]:
            lines.append(f"- `{loc['file']}:{loc['line']}` — {loc['name']}")
        if len(pb["affected_locations"]) > 20:
            lines.append(f"- *... and {len(pb['affected_locations']) - 20} more*")
        lines.append("")

        # Steps
        lines.append("### Remediation Steps")
        lines.append("")
        for i, step in enumerate(pb["steps"], 1):
            lines.append(f"**Step {i}: {step['action']}**")
            lines.append("")
            if "description" in step:
                lines.append(step["description"])
                lines.append("")
            if "command" in step:
                lines.append("```bash")
                lines.append(step["command"])
                lines.append("```")
                lines.append("")
            if "code_examples" in step:
                for lang, examples in step["code_examples"].items():
                    lines.append(f"*{lang.capitalize()}:*")
                    if "before" in examples:
                        lines.append("```")
                        lines.append(f"# Before (vulnerable):")
                        lines.append(examples["before"])
                        lines.append("")
                        lines.append(f"# After (safe):")
                        lines.append(examples["after"])
                        lines.append("```")
                    lines.append("")

        lines.extend(["---", ""])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Security Playbook Generator — create step-by-step remediation playbooks from scan findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input /tmp/pentest-results/ --format markdown --output /tmp/playbook.md
  %(prog)s --input static-results.json --output playbook.json
        """
    )
    parser.add_argument("--input", required=True, help="Scan results JSON file or directory")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input '{args.input}' does not exist", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(args.input)
    print(f"Loaded {len(findings)} findings", file=sys.stderr)

    playbooks = generate_playbooks(findings)
    print(f"Generated {len(playbooks)} remediation playbooks", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(playbooks, len(findings), args.input)
    else:
        output = json.dumps({
            "metadata": {
                "source": args.input,
                "generated": datetime.now(timezone.utc).isoformat(),
                "findings_total": len(findings),
                "playbooks_total": len(playbooks),
            },
            "playbooks": playbooks,
        }, indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Playbook written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
