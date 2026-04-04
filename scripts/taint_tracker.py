#!/usr/bin/env python3
"""
Taint Tracker — Traces user input from source to sink through the codebase
to verify if a vulnerability pattern is actually exploitable (reduces false positives).

Performs simplified data flow analysis: identifies where user input enters (sources),
where dangerous operations happen (sinks), and whether there's a path between them
without sanitization.

Usage:
    python taint_tracker.py --target <path> [--output <file>] [--format json|markdown]

Examples:
    python taint_tracker.py --target ./src --output /tmp/taint-results.json
    python taint_tracker.py --target ./app --format markdown
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── Source Definitions (where user input enters) ───

SOURCES = {
    "python": [
        (r"request\.(args|form|data|json|values|files|headers|cookies)\b", "flask/django request"),
        (r"request\.GET|request\.POST|request\.body", "django request"),
        (r"input\s*\(", "stdin input"),
        (r"sys\.argv", "command line argument"),
        (r"os\.environ", "environment variable"),
        (r"request\.params", "request parameters"),
    ],
    "javascript": [
        (r"req\.(body|params|query|headers|cookies)\b", "express request"),
        (r"request\.(body|params|query)\b", "http request"),
        (r"process\.argv", "command line argument"),
        (r"process\.env", "environment variable"),
        (r"document\.(location|URL|referrer|cookie)", "DOM source"),
        (r"window\.location", "browser location"),
        (r"URLSearchParams|location\.search|location\.hash", "URL parameters"),
    ],
    "java": [
        (r"request\.getParameter\s*\(", "servlet parameter"),
        (r"request\.getAttribute\s*\(", "request attribute"),
        (r"request\.getHeader\s*\(", "request header"),
        (r"@RequestParam|@PathVariable|@RequestBody", "spring parameter"),
        (r"Scanner\s*\(\s*System\.in", "stdin input"),
    ],
    "php": [
        (r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[", "superglobal"),
        (r"file_get_contents\s*\(\s*['\"]php://input", "raw body"),
        (r"\$argv", "command line argument"),
    ],
    "go": [
        (r"r\.FormValue\s*\(|r\.URL\.Query\(\)", "http form value"),
        (r"r\.Body|r\.Header\.Get", "http request"),
        (r"os\.Args", "command line argument"),
    ],
    "ruby": [
        (r"params\[", "rails params"),
        (r"request\.(body|headers|cookies)", "rack request"),
        (r"ARGV", "command line argument"),
    ],
    "csharp": [
        (r"Request\.(Form|Query|Params|Headers|Cookies)\[", "asp.net request"),
        (r"\[FromBody\]|\[FromQuery\]|\[FromRoute\]", "asp.net binding"),
        (r"args\[", "command line argument"),
    ],
}

# ─── Sink Definitions (where dangerous operations happen) ───

SINKS = {
    "sql_injection": {
        "patterns": {
            "python": [r"cursor\.execute\s*\(", r"\.raw\s*\(", r"\.extra\s*\(", r"engine\.execute\s*\("],
            "javascript": [r"\.query\s*\(", r"\.execute\s*\(", r"knex\.raw\s*\(", r"sequelize\.query\s*\("],
            "java": [r"executeQuery\s*\(", r"executeUpdate\s*\(", r"createQuery\s*\("],
            "php": [r"mysqli?_query\s*\(", r"pg_query\s*\(", r"\->query\s*\("],
            "go": [r"db\.(Query|Exec|QueryRow)\s*\("],
            "ruby": [r"\.where\s*\(", r"\.find_by_sql\s*\(", r"\.execute\s*\("],
            "csharp": [r"SqlCommand|ExecuteReader|ExecuteNonQuery"],
        },
        "cwe": "CWE-89", "severity": "critical",
    },
    "xss": {
        "patterns": {
            "python": [r"Markup\s*\(", r"mark_safe\s*\(", r"\|safe\b", r"render_template_string\s*\("],
            "javascript": [r"\.innerHTML\s*=", r"document\.write\s*\(", r"dangerouslySetInnerHTML", r"\.html\s*\("],
            "java": [r"\.write\s*\(.*getParameter", r"out\.println\s*\("],
            "php": [r"echo\s+\$", r"print\s+\$", r"<\?=\s*\$"],
        },
        "cwe": "CWE-79", "severity": "high",
    },
    "command_injection": {
        "patterns": {
            "python": [r"os\.system\s*\(", r"subprocess\.\w+\s*\(.*shell\s*=\s*True", r"os\.popen\s*\("],
            "javascript": [r"child_process\.exec\s*\(", r"child_process\.execSync\s*\("],
            "java": [r"Runtime\.getRuntime\(\)\.exec\s*\(", r"ProcessBuilder\s*\("],
            "php": [r"system\s*\(", r"exec\s*\(", r"passthru\s*\(", r"shell_exec\s*\(", r"popen\s*\("],
            "go": [r"exec\.Command\s*\("],
            "ruby": [r"system\s*\(", r"`.*#\{", r"IO\.popen\s*\("],
        },
        "cwe": "CWE-78", "severity": "critical",
    },
    "path_traversal": {
        "patterns": {
            "python": [r"open\s*\(", r"Path\s*\(", r"os\.path\.join\s*\("],
            "javascript": [r"fs\.(readFile|writeFile|readdir|unlink)\s*\(", r"path\.join\s*\("],
            "java": [r"new\s+File\s*\(", r"FileInputStream\s*\(", r"Files\.(read|write)\s*\("],
            "php": [r"fopen\s*\(", r"file_get_contents\s*\(", r"include\s*\(?\s*\$", r"require\s*\(?\s*\$"],
        },
        "cwe": "CWE-22", "severity": "high",
    },
    "ssrf": {
        "patterns": {
            "python": [r"requests\.(get|post|put|delete|patch)\s*\(", r"urllib\.request\.urlopen\s*\(", r"httpx\.\w+\s*\("],
            "javascript": [r"fetch\s*\(", r"axios\.\w+\s*\(", r"http\.get\s*\(", r"request\s*\("],
            "java": [r"HttpClient|HttpURLConnection|URL\s*\(\s*", r"RestTemplate"],
            "php": [r"curl_exec\s*\(", r"file_get_contents\s*\(.*https?://"],
        },
        "cwe": "CWE-918", "severity": "high",
    },
    "deserialization": {
        "patterns": {
            "python": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*SafeLoader)", r"marshal\.loads?\s*\("],
            "javascript": [r"unserialize\s*\(", r"JSON\.parse\s*\(.*eval"],
            "java": [r"ObjectInputStream|readObject\s*\(", r"XMLDecoder"],
            "php": [r"unserialize\s*\("],
        },
        "cwe": "CWE-502", "severity": "critical",
    },
}

# ─── Sanitizer Definitions (what breaks the taint chain) ───

SANITIZERS = {
    "sql_injection": {
        "python": [r"%s\s*,\s*\(", r"parameterized", r"\.filter\s*\(", r"prepared"],
        "javascript": [r"\$\d+\s*\]", r"\?\s*\]", r"parameterized", r"prepared", r"escape\s*\("],
        "java": [r"PreparedStatement", r"setString\s*\(", r"setInt\s*\("],
        "php": [r"prepare\s*\(", r"bind_param\s*\(", r"bindValue\s*\("],
    },
    "xss": {
        "python": [r"escape\s*\(", r"bleach\.\w+\s*\(", r"autoescape"],
        "javascript": [r"DOMPurify", r"sanitize\s*\(", r"textContent\s*=", r"encodeURIComponent"],
        "java": [r"StringEscapeUtils", r"HtmlUtils\.htmlEscape", r"ESAPI\.encoder"],
        "php": [r"htmlspecialchars\s*\(", r"htmlentities\s*\(", r"strip_tags\s*\("],
    },
    "command_injection": {
        "python": [r"shlex\.quote\s*\(", r"shell\s*=\s*False", r"subprocess\.run\s*\(\s*\["],
        "javascript": [r"execFile\s*\(", r"spawn\s*\("],
        "php": [r"escapeshellarg\s*\(", r"escapeshellcmd\s*\("],
    },
    "path_traversal": {
        "python": [r"os\.path\.realpath", r"os\.path\.abspath", r"\.startswith\s*\("],
        "javascript": [r"path\.resolve", r"path\.normalize", r"\.startsWith\s*\("],
        "java": [r"getCanonicalPath", r"normalize\s*\("],
    },
    "ssrf": {
        "python": [r"urlparse|ipaddress", r"ALLOWED_HOSTS|allowlist|whitelist"],
        "javascript": [r"URL\s*\(", r"allowlist|whitelist"],
    },
}

LANG_MAP = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby", ".cs": "csharp",
}


def detect_language(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    return LANG_MAP.get(ext)


def find_sources_in_file(filepath, language):
    """Find all taint sources in a file."""
    sources_found = []
    lang_sources = SOURCES.get(language, [])
    if not lang_sources:
        return sources_found

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except IOError:
        return sources_found

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for pattern, desc in lang_sources:
            if re.search(pattern, line):
                # Extract variable name being assigned
                var_match = re.match(r"\s*(\w+)\s*=", line)
                var_name = var_match.group(1) if var_match else None
                sources_found.append({
                    "file": filepath, "line": i,
                    "code": stripped[:150], "type": desc,
                    "variable": var_name,
                })

    return sources_found


def find_sinks_in_file(filepath, language):
    """Find all taint sinks in a file."""
    sinks_found = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except IOError:
        return sinks_found

    for sink_type, config in SINKS.items():
        lang_patterns = config["patterns"].get(language, [])
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern in lang_patterns:
                if re.search(pattern, line):
                    sinks_found.append({
                        "file": filepath, "line": i,
                        "code": stripped[:150], "type": sink_type,
                        "cwe": config["cwe"], "severity": config["severity"],
                    })

    return sinks_found


def check_sanitization(filepath, language, sink_type, source_line, sink_line):
    """Check if there's sanitization between source and sink."""
    sanitizer_patterns = SANITIZERS.get(sink_type, {}).get(language, [])
    if not sanitizer_patterns:
        return False

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except IOError:
        return False

    start = min(source_line, sink_line) - 1
    end = max(source_line, sink_line)
    region = "".join(lines[start:end])

    for pattern in sanitizer_patterns:
        if re.search(pattern, region):
            return True

    return False


def trace_taint(target):
    """Main taint tracking: find source->sink paths without sanitization."""
    findings = []
    stats = {"files_analyzed": 0, "sources_found": 0, "sinks_found": 0,
             "tainted_paths": 0, "sanitized_paths": 0}

    target_path = Path(target)
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}

    files = []
    if target_path.is_file():
        files = [target_path]
    else:
        for root, dirs, filenames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in filenames:
                fp = os.path.join(root, fn)
                if detect_language(fp):
                    files.append(fp)

    for filepath in files:
        language = detect_language(str(filepath))
        if not language:
            continue

        stats["files_analyzed"] += 1
        sources = find_sources_in_file(str(filepath), language)
        sinks = find_sinks_in_file(str(filepath), language)
        stats["sources_found"] += len(sources)
        stats["sinks_found"] += len(sinks)

        # For each source-sink pair in the same file, check for taint path
        for source in sources:
            for sink in sinks:
                # Simple heuristic: if source and sink are within 50 lines of each other
                line_distance = abs(source["line"] - sink["line"])
                if line_distance > 50:
                    continue

                # Check if source variable appears near the sink
                var = source.get("variable")
                if var and var in sink["code"]:
                    is_sanitized = check_sanitization(
                        str(filepath), language, sink["type"],
                        source["line"], sink["line"]
                    )

                    if is_sanitized:
                        stats["sanitized_paths"] += 1
                    else:
                        stats["tainted_paths"] += 1
                        findings.append({
                            "id": f"TAINT-{sink['cwe']}", "severity": sink["severity"],
                            "name": f"Unsanitized {sink['type']}: {var} flows to {sink['type']} sink",
                            "category": f"Taint: {source['type']} -> {sink['type']}",
                            "cwe": sink["cwe"],
                            "source": {
                                "file": source["file"], "line": source["line"],
                                "code": source["code"], "type": source["type"],
                                "variable": var,
                            },
                            "sink": {
                                "file": sink["file"], "line": sink["line"],
                                "code": sink["code"], "type": sink["type"],
                            },
                            "sanitized": False,
                            "description": (
                                f"User input from {source['type']} (variable '{var}') "
                                f"flows to {sink['type']} sink without sanitization"
                            ),
                            "fix": get_taint_fix(sink["type"], language),
                        })

    return {"findings": findings, "stats": stats}


def get_taint_fix(sink_type, language):
    fixes = {
        "sql_injection": {
            "python": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
            "javascript": "Use parameterized queries: db.query('SELECT * FROM t WHERE id = $1', [userId])",
            "java": "Use PreparedStatement with ? placeholders",
            "php": "Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * WHERE id = ?')",
        },
        "xss": {
            "python": "Use template auto-escaping. Never use mark_safe() on user input.",
            "javascript": "Use textContent instead of innerHTML. Sanitize with DOMPurify.",
        },
        "command_injection": {
            "python": "Use subprocess.run(['cmd', arg]) without shell=True",
            "javascript": "Use child_process.execFile() instead of exec()",
        },
        "path_traversal": {
            "python": "Use os.path.realpath() and verify path starts with allowed directory",
            "javascript": "Use path.resolve() and verify with startsWith()",
        },
        "ssrf": {
            "python": "Validate URL against allowlist. Block private IP ranges.",
        },
        "deserialization": {
            "python": "Use json.loads() instead of pickle.loads(). Use yaml.safe_load().",
        },
    }
    lang_fixes = fixes.get(sink_type, {})
    return lang_fixes.get(language, f"Sanitize user input before passing to {sink_type} sink")


def format_markdown(results, target):
    findings = results["findings"]
    stats = results["stats"]

    lines = [
        "# Taint Analysis Report",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Statistics",
        f"- Files analyzed: {stats['files_analyzed']}",
        f"- Taint sources found: {stats['sources_found']}",
        f"- Dangerous sinks found: {stats['sinks_found']}",
        f"- **Unsanitized taint paths: {stats['tainted_paths']}** (confirmed vulnerable)",
        f"- Sanitized paths: {stats['sanitized_paths']} (false positives eliminated)",
        "",
    ]

    if stats['sources_found'] > 0 and stats['sinks_found'] > 0:
        fp_rate = stats['sanitized_paths'] / max(1, stats['sanitized_paths'] + stats['tainted_paths']) * 100
        lines.append(f"**False positive reduction: {fp_rate:.0f}%** of potential findings eliminated by taint tracking")
        lines.append("")

    if findings:
        lines.extend(["---", "", "## Confirmed Taint Paths", ""])
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4)):
            src = f["source"]
            snk = f["sink"]
            lines.extend([
                f"### [{f['severity'].upper()}] {f['name']}",
                f"- **CWE:** {f['cwe']}",
                f"- **Source:** `{src['file']}:{src['line']}` ({src['type']})",
                f"  ```", f"  {src['code']}", f"  ```",
                f"- **Sink:** `{snk['file']}:{snk['line']}` ({snk['type']})",
                f"  ```", f"  {snk['code']}", f"  ```",
                f"- **Variable:** `{src.get('variable', 'N/A')}`",
                f"- **Fix:** {f['fix']}",
                "",
            ])
    else:
        lines.append("No unsanitized taint paths found. All source-to-sink flows appear to be sanitized.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Taint Tracker — trace user input from source to sink to verify exploitability",
    )
    parser.add_argument("--target", required=True, help="Source code file or directory")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target '{args.target}' does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing taint paths in {args.target}...", file=sys.stderr)
    results = trace_taint(args.target)

    stats = results["stats"]
    print(f"[*] Files: {stats['files_analyzed']} | Sources: {stats['sources_found']} | "
          f"Sinks: {stats['sinks_found']} | Tainted: {stats['tainted_paths']} | "
          f"Sanitized: {stats['sanitized_paths']}", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(results, args.target)
    else:
        output = json.dumps(results, indent=2, default=str)

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
