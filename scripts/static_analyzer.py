#!/usr/bin/env python3
"""
Static Security Analyzer — Pattern-based vulnerability scanner for source code.
Scans for 50+ vulnerability patterns across multiple languages.

Usage:
    python static_analyzer.py --target <path> [--language <lang>] [--output <file>] [--format json|markdown] [--severity critical|high|medium|low|all]

Examples:
    python static_analyzer.py --target ./src --output results.json
    python static_analyzer.py --target ./app.py --language python --severity high
    python static_analyzer.py --target ./project --format markdown --output report.md
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─── Vulnerability Pattern Database ───

PATTERNS = {
    "python": [
        # Injection
        {"id": "PY-INJ-001", "name": "SQL Injection (string formatting)", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:execute|cursor\.execute|\.raw|\.extra)\s*\(\s*(?:f["\']|["\'].*%s|["\'].*\{|["\'].*\+)""",
         "description": "SQL query constructed with string formatting/concatenation — vulnerable to SQL injection",
         "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"},
        {"id": "PY-INJ-002", "name": "Command Injection (shell=True)", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True""",
         "description": "Shell command execution with shell=True — if user input reaches this, it's command injection",
         "fix": "Use subprocess with array arguments and shell=False: subprocess.run(['cmd', 'arg1', 'arg2'])"},
        {"id": "PY-INJ-003", "name": "eval() with potential user input", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-95",
         "pattern": r"""\beval\s*\(""",
         "description": "eval() executes arbitrary Python code — if user input can reach it, it's RCE",
         "fix": "Use ast.literal_eval() for data parsing, or avoid eval entirely"},
        {"id": "PY-INJ-004", "name": "exec() usage", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-95",
         "pattern": r"""\bexec\s*\(""",
         "description": "exec() executes arbitrary Python code",
         "fix": "Avoid exec() — use safe alternatives or sandbox execution"},
        {"id": "PY-INJ-005", "name": "os.system() usage", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""os\.system\s*\(""",
         "description": "os.system() executes shell commands — highly vulnerable to injection",
         "fix": "Use subprocess.run() with array arguments and shell=False"},
        {"id": "PY-INJ-006", "name": "Template injection (render_template_string)", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-1336",
         "pattern": r"""render_template_string\s*\(.*(?:format|%|\+|\{)""",
         "description": "Server-side template injection via user-controlled template string",
         "fix": "Use render_template() with separate template files, pass user data as variables"},

        # Deserialization
        {"id": "PY-DES-001", "name": "Unsafe pickle deserialization", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""pickle\.(?:loads?|Unpickler)\s*\(""",
         "description": "pickle.loads() can execute arbitrary code during deserialization",
         "fix": "Use json.loads() for data exchange, or hmac-verify pickled data before loading"},
        {"id": "PY-DES-002", "name": "Unsafe YAML loading", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""yaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)""",
         "description": "yaml.load() without SafeLoader can execute arbitrary Python code",
         "fix": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"},

        # Cryptography
        {"id": "PY-CRY-001", "name": "MD5 usage", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-327",
         "pattern": r"""(?:hashlib\.md5|MD5\.new|md5\()""",
         "description": "MD5 is cryptographically broken — not suitable for security purposes",
         "fix": "Use SHA-256+ for checksums, bcrypt/argon2 for passwords"},
        {"id": "PY-CRY-002", "name": "SHA1 for security", "severity": "medium", "category": "A02:2021-Crypto", "cwe": "CWE-327",
         "pattern": r"""hashlib\.sha1""",
         "description": "SHA1 is deprecated for security purposes",
         "fix": "Use SHA-256 or SHA-3 for hashing, bcrypt/argon2 for passwords"},
        {"id": "PY-CRY-003", "name": "Hardcoded secret key", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
         "pattern": r"""(?:SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*["\'][^"\']{8,}["\']""",
         "description": "Hardcoded secret in source code — will be in version control",
         "fix": "Use environment variables: os.environ['SECRET_KEY']"},
        {"id": "PY-CRY-004", "name": "Weak random for security", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-330",
         "pattern": r"""random\.(?:random|randint|choice|randrange)\s*\(""",
         "description": "random module is not cryptographically secure",
         "fix": "Use secrets module: secrets.token_hex(), secrets.randbelow()"},

        # SSL/TLS
        {"id": "PY-TLS-001", "name": "SSL verification disabled", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-295",
         "pattern": r"""verify\s*=\s*False""",
         "description": "SSL certificate verification disabled — vulnerable to MITM attacks",
         "fix": "Always use verify=True (default) or provide a CA bundle"},

        # Configuration
        {"id": "PY-CFG-001", "name": "Debug mode enabled", "severity": "high", "category": "A05:2021-Misconfig", "cwe": "CWE-489",
         "pattern": r"""DEBUG\s*=\s*True""",
         "description": "Debug mode exposes detailed error pages and stack traces",
         "fix": "Set DEBUG = False in production, use environment variable"},

        # SSRF
        {"id": "PY-SSRF-001", "name": "Potential SSRF", "severity": "high", "category": "A10:2021-SSRF", "cwe": "CWE-918",
         "pattern": r"""requests\.(?:get|post|put|delete|patch|head)\s*\(.*(?:url|uri|href|link|target|redirect|callback)""",
         "description": "HTTP request with potentially user-controlled URL — SSRF risk",
         "fix": "Validate URL against allowlist, block internal/private IP ranges"},

        # XSS
        {"id": "PY-XSS-001", "name": "Markup/safe filter bypass", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""(?:Markup\(|mark_safe\(|\|safe\b|\|raw\b)""",
         "description": "Disabling template auto-escaping — XSS risk if user input reaches this",
         "fix": "Only mark trusted content as safe, never user input"},

        # File operations
        {"id": "PY-PATH-001", "name": "Path traversal risk", "severity": "high", "category": "A01:2021-Access", "cwe": "CWE-22",
         "pattern": r"""(?:open|Path)\s*\(.*(?:request|params|input|argv|args)""",
         "description": "File operation with user-controlled path — path traversal risk",
         "fix": "Use os.path.realpath() and verify the resolved path is within allowed directory"},
    ],

    "javascript": [
        # Injection
        {"id": "JS-INJ-001", "name": "eval() usage", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-95",
         "pattern": r"""\beval\s*\(""",
         "description": "eval() executes arbitrary JavaScript — RCE in Node.js, XSS in browser",
         "fix": "Use JSON.parse() for data, avoid eval entirely"},
        {"id": "JS-INJ-002", "name": "innerHTML assignment", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""\.innerHTML\s*=(?!=)""",
         "description": "Direct innerHTML assignment — XSS if user input is included",
         "fix": "Use textContent for text, DOMPurify.sanitize() for HTML"},
        {"id": "JS-INJ-003", "name": "document.write()", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""document\.write\s*\(""",
         "description": "document.write() with user input enables XSS",
         "fix": "Use DOM APIs (createElement, textContent) instead"},
        {"id": "JS-INJ-004", "name": "dangerouslySetInnerHTML", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""dangerouslySetInnerHTML""",
         "description": "React's escape hatch for raw HTML — XSS risk",
         "fix": "Sanitize with DOMPurify before using, or avoid if possible"},
        {"id": "JS-INJ-005", "name": "child_process.exec()", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""child_process\.exec\s*\(""",
         "description": "Shell command execution — command injection if user input is included",
         "fix": "Use child_process.execFile() or spawn() with array arguments"},
        {"id": "JS-INJ-006", "name": "SQL string concatenation", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|["\'].*\+)""",
         "description": "SQL query built with string concatenation/template literals",
         "fix": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])"},
        {"id": "JS-INJ-007", "name": "new Function() constructor", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-95",
         "pattern": r"""new\s+Function\s*\(""",
         "description": "Function constructor is equivalent to eval()",
         "fix": "Avoid dynamic code generation from user input"},

        # Cryptography
        {"id": "JS-CRY-001", "name": "Math.random() for security", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-330",
         "pattern": r"""Math\.random\s*\(\s*\)""",
         "description": "Math.random() is not cryptographically secure",
         "fix": "Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser)"},
        {"id": "JS-CRY-002", "name": "Hardcoded secret", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
         "pattern": r"""(?:secret|password|apiKey|api_key|token)\s*[:=]\s*["\'][^"\']{8,}["\']""",
         "description": "Hardcoded secret in source code",
         "fix": "Use environment variables: process.env.SECRET_KEY"},

        # JWT
        {"id": "JS-JWT-001", "name": "JWT without algorithm restriction", "severity": "critical", "category": "A07:2021-Auth", "cwe": "CWE-345",
         "pattern": r"""jwt\.verify\s*\([^)]*\)\s*(?!.*algorithms)""",
         "description": "JWT verification without explicit algorithm — algorithm confusion attack possible",
         "fix": "Specify algorithms: jwt.verify(token, key, { algorithms: ['RS256'] })"},

        # Configuration
        {"id": "JS-CFG-001", "name": "CORS wildcard", "severity": "high", "category": "A05:2021-Misconfig", "cwe": "CWE-942",
         "pattern": r"""(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*["\']?\*""",
         "description": "CORS allows all origins — any website can make requests to this API",
         "fix": "Restrict to specific trusted origins"},
        {"id": "JS-CFG-002", "name": "Helmet/security headers missing", "severity": "medium", "category": "A05:2021-Misconfig", "cwe": "CWE-693",
         "pattern": r"""express\s*\(\s*\)""",
         "description": "Express app created — verify helmet middleware is used for security headers",
         "fix": "Add: const helmet = require('helmet'); app.use(helmet());"},

        # Prototype pollution
        {"id": "JS-PP-001", "name": "Potential prototype pollution", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-1321",
         "pattern": r"""(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|\.\.\.\s*(?:req\.body|req\.query|req\.params))""",
         "description": "Deep merge/spread of user input can lead to prototype pollution",
         "fix": "Validate input structure, use Object.create(null) for dictionaries, or use a safe merge library"},

        # Session
        {"id": "JS-SES-001", "name": "Session stored in memory", "severity": "medium", "category": "A07:2021-Auth", "cwe": "CWE-613",
         "pattern": r"""MemoryStore""",
         "description": "In-memory session store — memory leak, lost on restart, not scalable",
         "fix": "Use Redis, database, or other persistent session store"},
    ],

    "java": [
        {"id": "JV-INJ-001", "name": "SQL Injection (string concatenation)", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:executeQuery|executeUpdate|execute)\s*\(\s*["\'].*\+""",
         "description": "SQL query built with string concatenation",
         "fix": "Use PreparedStatement with parameterized queries"},
        {"id": "JV-INJ-002", "name": "Command injection (Runtime.exec)", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""Runtime\.getRuntime\(\)\.exec\s*\(""",
         "description": "OS command execution — injection risk if user input is included",
         "fix": "Use ProcessBuilder with array arguments, validate input"},
        {"id": "JV-DES-001", "name": "Unsafe deserialization", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""ObjectInputStream|readObject\s*\(""",
         "description": "Java deserialization can lead to RCE via gadget chains",
         "fix": "Use a serialization filter, or switch to JSON/protobuf"},
        {"id": "JV-XXE-001", "name": "XML parsing without XXE protection", "severity": "high", "category": "A05:2021-Misconfig", "cwe": "CWE-611",
         "pattern": r"""DocumentBuilderFactory\.newInstance\(\)(?!.*setFeature)""",
         "description": "XML parser without external entity protection",
         "fix": "Disable DTDs and external entities via setFeature()"},
        {"id": "JV-CRY-001", "name": "Weak algorithm (MD5/SHA1)", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-327",
         "pattern": r"""MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\']""",
         "description": "Weak hashing algorithm — not suitable for security",
         "fix": "Use SHA-256+ for checksums, bcrypt for passwords"},
        {"id": "JV-LOG-001", "name": "Log injection", "severity": "medium", "category": "A09:2021-Logging", "cwe": "CWE-117",
         "pattern": r"""(?:log|logger)\.(?:info|debug|warn|error)\s*\(.*(?:request|param|input|getParameter)""",
         "description": "User input in log messages — log injection/forging risk",
         "fix": "Sanitize user input before logging (remove newlines, control chars)"},
    ],

    "php": [
        {"id": "PHP-INJ-001", "name": "SQL Injection", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:mysql_query|mysqli_query|pg_query)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)""",
         "description": "Direct use of user input in SQL query",
         "fix": "Use prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');"},
        {"id": "PHP-INJ-002", "name": "Command injection", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*\$""",
         "description": "Shell command with variable input — command injection",
         "fix": "Use escapeshellarg() for arguments, or avoid shell execution"},
        {"id": "PHP-INJ-003", "name": "eval() usage", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-95",
         "pattern": r"""\beval\s*\(\s*\$""",
         "description": "eval() with variable input — arbitrary code execution",
         "fix": "Avoid eval() — use safe alternatives"},
        {"id": "PHP-DES-001", "name": "Unsafe deserialization", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""unserialize\s*\(.*\$""",
         "description": "unserialize() with user input — object injection / RCE",
         "fix": "Use json_decode() for data exchange, or add allowed_classes filter"},
        {"id": "PHP-XSS-001", "name": "Unescaped output", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""echo\s+\$_(?:GET|POST|REQUEST|COOKIE)""",
         "description": "Direct output of user input without escaping — XSS",
         "fix": "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8')"},
        {"id": "PHP-FI-001", "name": "File inclusion", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-98",
         "pattern": r"""(?:include|require|include_once|require_once)\s*\(?\s*\$""",
         "description": "Dynamic file inclusion with user input — LFI/RFI",
         "fix": "Use allowlist of permitted files, never include user-controlled paths"},
        {"id": "PHP-CFG-001", "name": "Error display enabled", "severity": "medium", "category": "A05:2021-Misconfig", "cwe": "CWE-209",
         "pattern": r"""display_errors\s*=\s*(?:On|1|true)""",
         "description": "PHP errors displayed to users — information disclosure",
         "fix": "Set display_errors = Off in production, log errors to file instead"},
    ],

    "go": [
        {"id": "GO-INJ-001", "name": "SQL string concatenation", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|["\'].*\+)""",
         "description": "SQL query with string formatting — SQL injection risk",
         "fix": "Use parameterized queries: db.Query('SELECT * FROM users WHERE id = $1', userId)"},
        {"id": "GO-INJ-002", "name": "Command execution", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""exec\.Command\s*\(\s*["\'](?:sh|bash|cmd)["\']""",
         "description": "Shell command execution — injection risk if arguments contain user input",
         "fix": "Use exec.Command with separate arguments, validate input"},
        {"id": "GO-TLS-001", "name": "TLS verification disabled", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-295",
         "pattern": r"""InsecureSkipVerify\s*:\s*true""",
         "description": "TLS certificate verification disabled — MITM vulnerability",
         "fix": "Remove InsecureSkipVerify or set to false"},
        {"id": "GO-CRY-001", "name": "Weak random", "severity": "high", "category": "A02:2021-Crypto", "cwe": "CWE-330",
         "pattern": r"""math/rand""",
         "description": "math/rand is not cryptographically secure",
         "fix": "Use crypto/rand for security-sensitive random values"},
    ],

    "csharp": [
        {"id": "CS-INJ-001", "name": "SQL Injection", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(?\s*["\'].*\+""",
         "description": "SQL query with string concatenation",
         "fix": "Use SqlParameter with parameterized queries"},
        {"id": "CS-INJ-002", "name": "Process.Start with user input", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""Process\.Start\s*\(""",
         "description": "OS command execution — validate that arguments are not user-controlled",
         "fix": "Use ProcessStartInfo with argument array, validate input"},
        {"id": "CS-DES-001", "name": "BinaryFormatter deserialization", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter""",
         "description": "Unsafe deserialization — RCE via gadget chains",
         "fix": "Use System.Text.Json or JsonSerializer instead"},
        {"id": "CS-XSS-001", "name": "Raw HTML output", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""@Html\.Raw\s*\(""",
         "description": "Rendering raw HTML — XSS risk if user input is included",
         "fix": "Use @Html.Encode() or let Razor auto-escape"},
    ],

    "ruby": [
        {"id": "RB-INJ-001", "name": "SQL string interpolation", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-89",
         "pattern": r"""(?:where|find_by_sql|execute|select)\s*\(\s*["'].*#\{""",
         "description": "SQL query with string interpolation — SQL injection",
         "fix": "Use parameterized queries: User.where('name = ?', params[:name])"},
        {"id": "RB-INJ-002", "name": "System/exec/backtick command", "severity": "critical", "category": "A03:2021-Injection", "cwe": "CWE-78",
         "pattern": r"""(?:system|exec|`.*#\{|\%x\[)""",
         "description": "Shell command with interpolated input",
         "fix": "Use Open3.capture3 or Shellwords.escape"},
        {"id": "RB-DES-001", "name": "Marshal.load from untrusted", "severity": "critical", "category": "A08:2021-Integrity", "cwe": "CWE-502",
         "pattern": r"""Marshal\.load""",
         "description": "Marshal.load can execute arbitrary code",
         "fix": "Use JSON.parse for data exchange"},
        {"id": "RB-XSS-001", "name": "html_safe on user input", "severity": "high", "category": "A03:2021-Injection", "cwe": "CWE-79",
         "pattern": r"""\.html_safe|raw\s*\(""",
         "description": "Marking content as HTML-safe bypasses auto-escaping",
         "fix": "Only use html_safe on trusted content, sanitize user input first"},
    ],
}

# Language detection by file extension
LANG_MAP = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java",
    ".php": "php", ".phtml": "php",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby", ".erb": "ruby",
}

# Generic patterns (all languages)
GENERIC_PATTERNS = [
    {"id": "GEN-SEC-001", "name": "Hardcoded password", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
     "pattern": r"""(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']""",
     "description": "Hardcoded password in source code",
     "fix": "Use environment variables or a secrets manager"},
    {"id": "GEN-SEC-002", "name": "Hardcoded API key", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
     "pattern": r"""(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']""",
     "description": "Hardcoded API key in source code",
     "fix": "Use environment variables or a secrets manager"},
    {"id": "GEN-SEC-003", "name": "Private key in source", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-321",
     "pattern": r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""",
     "description": "Private key embedded in source code",
     "fix": "Store private keys in secure key management system, never in code"},
    {"id": "GEN-SEC-004", "name": "AWS access key", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
     "pattern": r"""AKIA[0-9A-Z]{16}""",
     "description": "AWS access key ID found in source code",
     "fix": "Use IAM roles or AWS Secrets Manager, rotate the exposed key immediately"},
    {"id": "GEN-SEC-005", "name": "TODO/FIXME security", "severity": "low", "category": "A05:2021-Misconfig", "cwe": "CWE-0",
     "pattern": r"""(?:TODO|FIXME|HACK|XXX).*(?:security|auth|password|token|secret|vulnerability|insecure|unsafe)""",
     "description": "Security-related TODO/FIXME comment — may indicate known unfixed issue",
     "fix": "Address the security concern described in the comment"},
    {"id": "GEN-SEC-006", "name": "HTTP URL (non-localhost)", "severity": "low", "category": "A02:2021-Crypto", "cwe": "CWE-319",
     "pattern": r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])[\w.-]+""",
     "description": "HTTP URL used — data transmitted without encryption",
     "fix": "Use HTTPS for all external communications"},
    {"id": "GEN-SEC-007", "name": "IP address hardcoded", "severity": "info", "category": "A05:2021-Misconfig", "cwe": "CWE-0",
     "pattern": r"""\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b""",
     "description": "Internal IP address in source code — potential information disclosure",
     "fix": "Use configuration files or environment variables for network addresses"},
    {"id": "GEN-SEC-008", "name": "Connection string with credentials", "severity": "critical", "category": "A02:2021-Crypto", "cwe": "CWE-798",
     "pattern": r"""(?:mongodb|postgres|mysql|redis|amqp|mssql)://[^:]+:[^@]+@""",
     "description": "Database connection string with embedded credentials",
     "fix": "Use environment variables for connection strings"},
]


def detect_language(filepath: str) -> Optional[str]:
    ext = os.path.splitext(filepath)[1].lower()
    return LANG_MAP.get(ext)


def scan_file(filepath: str, language: Optional[str] = None, severity_filter: str = "all") -> list:
    findings = []
    lang = language or detect_language(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    filter_level = severity_order.get(severity_filter, 4)

    patterns_to_check = list(GENERIC_PATTERNS)
    if lang and lang in PATTERNS:
        patterns_to_check.extend(PATTERNS[lang])

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern_def in patterns_to_check:
            sev = severity_order.get(pattern_def["severity"], 4)
            if sev > filter_level:
                continue

            try:
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "id": pattern_def["id"],
                        "name": pattern_def["name"],
                        "severity": pattern_def["severity"],
                        "category": pattern_def["category"],
                        "cwe": pattern_def["cwe"],
                        "file": filepath,
                        "line": i,
                        "code": stripped[:200],
                        "description": pattern_def["description"],
                        "fix": pattern_def["fix"],
                    })
            except re.error:
                continue

    return findings


def scan_directory(target: str, language: Optional[str] = None, severity_filter: str = "all") -> list:
    all_findings = []
    target_path = Path(target)

    if target_path.is_file():
        return scan_file(str(target_path), language, severity_filter)

    skip_dirs = {
        "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        "vendor", ".bundle", "target", "bin", "obj", ".next", ".nuxt",
    }

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext in LANG_MAP or (language and ext):
                file_lang = language or LANG_MAP.get(ext)
                findings = scan_file(filepath, file_lang, severity_filter)
                all_findings.extend(findings)

    return all_findings


def generate_summary(findings: list) -> dict:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts = {}
    files_affected = set()

    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        cat = f["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
        files_affected.add(f["file"])

    total = len(findings)
    risk_score = min(100, (
        severity_counts["critical"] * 25 +
        severity_counts["high"] * 15 +
        severity_counts["medium"] * 5 +
        severity_counts["low"] * 1
    ))

    return {
        "total_findings": total,
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "files_affected": len(files_affected),
        "risk_score": risk_score,
    }


def format_markdown(findings: list, summary: dict, target: str) -> str:
    lines = [
        f"# Static Analysis Report",
        f"**Target:** {target}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Risk Score:** {summary['risk_score']}/100",
        "",
        "## Summary",
        f"- **Total findings:** {summary['total_findings']}",
        f"- **Critical:** {summary['severity_breakdown']['critical']}",
        f"- **High:** {summary['severity_breakdown']['high']}",
        f"- **Medium:** {summary['severity_breakdown']['medium']}",
        f"- **Low:** {summary['severity_breakdown']['low']}",
        f"- **Files affected:** {summary['files_affected']}",
        "",
        "## Findings",
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 4))

    for f in sorted_findings:
        sev_upper = f["severity"].upper()
        lines.extend([
            f"### [{sev_upper}] {f['name']} ({f['id']})",
            f"- **Category:** {f['category']}",
            f"- **CWE:** {f['cwe']}",
            f"- **File:** `{f['file']}:{f['line']}`",
            f"- **Code:** `{f['code']}`",
            f"- **Description:** {f['description']}",
            f"- **Fix:** {f['fix']}",
            "",
        ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Static Security Analyzer — scan source code for vulnerability patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target ./src --output results.json
  %(prog)s --target ./app.py --language python --severity high
  %(prog)s --target ./project --format markdown --output report.md
        """
    )
    parser.add_argument("--target", required=True, help="File or directory to scan")
    parser.add_argument("--language", choices=list(PATTERNS.keys()), help="Force language (auto-detected by default)")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format (default: json)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "all"], default="all", help="Minimum severity to report")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target '{args.target}' does not exist", file=sys.stderr)
        sys.exit(1)

    findings = scan_directory(args.target, args.language, args.severity)
    summary = generate_summary(findings)

    if args.format == "markdown":
        output = format_markdown(findings, summary, args.target)
    else:
        output = json.dumps({"summary": summary, "findings": findings}, indent=2)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
        print(f"Found {summary['total_findings']} issues (Risk Score: {summary['risk_score']}/100)", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
