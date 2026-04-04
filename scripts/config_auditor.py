#!/usr/bin/env python3
"""
Configuration Security Auditor — Scans configuration files, environment variables,
Docker configs, CI/CD pipelines, and infrastructure-as-code for security issues.

Usage:
    python config_auditor.py --target <path> [--output <file>] [--format json|markdown]

Examples:
    python config_auditor.py --target ./myproject
    python config_auditor.py --target . --format markdown --output config-report.md
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─── Configuration Security Rules ───

ENV_RULES = [
    {"id": "CFG-ENV-001", "name": "DEBUG mode enabled", "severity": "high",
     "pattern": r"^(?:DEBUG|APP_DEBUG)\s*=\s*(?:true|True|TRUE|1|yes)\s*$",
     "description": "Debug mode enabled — exposes stack traces and internal details",
     "fix": "Set DEBUG=false in production"},
    {"id": "CFG-ENV-002", "name": "Default/weak secret key", "severity": "critical",
     "pattern": r"^(?:SECRET_KEY|APP_KEY|JWT_SECRET)\s*=\s*(?:change.?me|secret|password|test|example|default|your.?secret|CHANGE_ME|TODO|xxx|yyy)",
     "description": "Default or placeholder secret key — trivially guessable",
     "fix": "Generate a strong random secret: python -c 'import secrets; print(secrets.token_hex(32))'"},
    {"id": "CFG-ENV-003", "name": "Database password in env file", "severity": "high",
     "pattern": r"^(?:DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|MONGO_PASSWORD)\s*=\s*.{1,}$",
     "description": "Database password in .env file — risk if committed to version control",
     "fix": "Ensure .env is in .gitignore. Use a secrets manager in production"},
    {"id": "CFG-ENV-004", "name": "API key in env file", "severity": "high",
     "pattern": r"^(?:API_KEY|OPENAI_API_KEY|STRIPE_SECRET_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SENDGRID_API_KEY)\s*=\s*.{8,}$",
     "description": "API key/secret in .env file",
     "fix": "Ensure .env is in .gitignore. Use a secrets manager in production"},
    {"id": "CFG-ENV-005", "name": "Insecure database URL", "severity": "high",
     "pattern": r"^(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*=\s*(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@",
     "description": "Database connection string with embedded credentials",
     "fix": "Use separate DB_HOST, DB_USER, DB_PASSWORD variables or a secrets manager"},
    {"id": "CFG-ENV-006", "name": "CORS allow all origins", "severity": "medium",
     "pattern": r"^(?:CORS_ORIGIN|ALLOWED_ORIGINS|CORS_ALLOWED_ORIGINS)\s*=\s*\*",
     "description": "CORS configured to allow all origins",
     "fix": "Restrict to specific trusted domains"},
    {"id": "CFG-ENV-007", "name": "SSL/TLS disabled", "severity": "high",
     "pattern": r"^(?:SSL_VERIFY|TLS_VERIFY|VERIFY_SSL|NODE_TLS_REJECT_UNAUTHORIZED)\s*=\s*(?:false|False|FALSE|0|no)",
     "description": "SSL/TLS verification disabled — vulnerable to MITM attacks",
     "fix": "Enable SSL verification in production"},
]

DOCKER_RULES = [
    {"id": "CFG-DOC-001", "name": "Running as root", "severity": "high",
     "pattern": r"^(?!.*USER\s+\S)(?=.*(?:FROM|CMD|ENTRYPOINT)).*$",
     "check_type": "no_user_directive",
     "description": "Container runs as root — if compromised, attacker has root access",
     "fix": "Add USER directive: RUN adduser -D appuser && USER appuser"},
    {"id": "CFG-DOC-002", "name": "Using :latest tag", "severity": "medium",
     "pattern": r"^FROM\s+\S+:latest",
     "description": "Using :latest tag — builds are not reproducible, may pull vulnerable versions",
     "fix": "Pin to specific version: FROM node:20-alpine"},
    {"id": "CFG-DOC-003", "name": "COPY of secrets", "severity": "critical",
     "pattern": r"^(?:COPY|ADD)\s+.*(?:\.env|\.key|\.pem|id_rsa|credentials|secrets)",
     "description": "Copying secret files into Docker image — they persist in image layers",
     "fix": "Use Docker secrets, mount at runtime, or use multi-stage builds"},
    {"id": "CFG-DOC-004", "name": "Exposed sensitive port", "severity": "medium",
     "pattern": r"^EXPOSE\s+(?:22|3306|5432|6379|27017|9200)\b",
     "description": "Exposing database/admin port directly",
     "fix": "Use Docker networks for inter-container communication instead of exposing ports"},
    {"id": "CFG-DOC-005", "name": "ADD instead of COPY", "severity": "low",
     "pattern": r"^ADD\s+(?!https?://)",
     "description": "ADD can have unexpected behaviors (auto-extraction). COPY is more explicit",
     "fix": "Use COPY instead of ADD for local files"},
    {"id": "CFG-DOC-006", "name": "Privileged mode in compose", "severity": "critical",
     "pattern": r"privileged:\s*true",
     "description": "Container running in privileged mode — full host access",
     "fix": "Remove privileged: true, use specific capabilities instead"},
    {"id": "CFG-DOC-007", "name": "Docker socket mounted", "severity": "critical",
     "pattern": r"/var/run/docker\.sock",
     "description": "Docker socket mounted — allows container to control host Docker daemon",
     "fix": "Remove Docker socket mount unless absolutely required"},
]

CICD_RULES = [
    {"id": "CFG-CI-001", "name": "Unpinned GitHub Action", "severity": "high",
     "pattern": r"uses:\s+\S+@(?:master|main|latest)\b",
     "description": "GitHub Action pinned to mutable tag — supply chain attack vector",
     "fix": "Pin to specific commit SHA: uses: actions/checkout@abc123..."},
    {"id": "CFG-CI-002", "name": "Secret in workflow file", "severity": "critical",
     "pattern": r"(?:password|token|secret|key)\s*[:=]\s*[\"'][^\"'$]+[\"']",
     "description": "Hardcoded secret in CI/CD pipeline",
     "fix": "Use repository secrets: ${{ secrets.MY_SECRET }}"},
    {"id": "CFG-CI-003", "name": "Pull request trigger on target", "severity": "medium",
     "pattern": r"pull_request_target",
     "description": "pull_request_target runs with write permissions — code injection risk from PRs",
     "fix": "Use pull_request event instead, or carefully restrict the workflow"},
    {"id": "CFG-CI-004", "name": "Unsafe script injection", "severity": "high",
     "pattern": r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body|label)",
     "description": "User-controlled GitHub event data used in run: step — command injection",
     "fix": "Pass as environment variable: env: TITLE: ${{ github.event.issue.title }}"},
]

GITIGNORE_EXPECTED = [
    ".env", ".env.local", ".env.production", ".env.*",
    "*.pem", "*.key", "*.p12", "*.pfx",
    "id_rsa", "id_ed25519",
    "credentials.json", "service-account.json",
    "*.sqlite", "*.db",
]

SECURITY_HEADERS_NGINX = {
    "X-Content-Type-Options": r"add_header\s+X-Content-Type-Options",
    "X-Frame-Options": r"add_header\s+X-Frame-Options",
    "Strict-Transport-Security": r"add_header\s+Strict-Transport-Security",
    "Content-Security-Policy": r"add_header\s+Content-Security-Policy",
    "Referrer-Policy": r"add_header\s+Referrer-Policy",
}


def scan_env_files(target: str) -> list:
    findings = []
    env_patterns = ["**/.env", "**/.env.*", "**/.env.local", "**/.env.production"]

    for pattern in env_patterns:
        for filepath in Path(target).glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        for rule in ENV_RULES:
                            if re.match(rule["pattern"], line, re.IGNORECASE):
                                findings.append({
                                    "id": rule["id"],
                                    "name": rule["name"],
                                    "severity": rule["severity"],
                                    "file": str(filepath),
                                    "line": i,
                                    "content": line[:100] + ("..." if len(line) > 100 else ""),
                                    "description": rule["description"],
                                    "fix": rule["fix"],
                                })
            except IOError:
                continue

    return findings


def scan_dockerfiles(target: str) -> list:
    findings = []
    docker_patterns = ["**/Dockerfile", "**/Dockerfile.*", "**/docker-compose*.yml", "**/docker-compose*.yaml"]

    for pattern in docker_patterns:
        for filepath in Path(target).glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    for rule in DOCKER_RULES:
                        if rule.get("check_type") == "no_user_directive":
                            continue
                        if re.search(rule["pattern"], line, re.IGNORECASE):
                            findings.append({
                                "id": rule["id"],
                                "name": rule["name"],
                                "severity": rule["severity"],
                                "file": str(filepath),
                                "line": i,
                                "content": line.strip()[:100],
                                "description": rule["description"],
                                "fix": rule["fix"],
                            })

                # Check for missing USER directive in Dockerfiles
                if filepath.name.startswith("Dockerfile"):
                    has_user = any(re.match(r"^\s*USER\s+\S", line) for line in lines)
                    has_from = any(re.match(r"^\s*FROM\s+", line) for line in lines)
                    if has_from and not has_user:
                        findings.append({
                            "id": "CFG-DOC-001",
                            "name": "Running as root (no USER directive)",
                            "severity": "high",
                            "file": str(filepath),
                            "line": 1,
                            "content": "No USER directive found",
                            "description": "Container runs as root — if compromised, attacker has root access",
                            "fix": "Add USER directive: RUN adduser -D appuser && USER appuser",
                        })

            except IOError:
                continue

    return findings


def scan_cicd(target: str) -> list:
    findings = []
    cicd_patterns = [
        "**/.github/workflows/*.yml",
        "**/.github/workflows/*.yaml",
        "**/.gitlab-ci.yml",
        "**/Jenkinsfile",
        "**/.circleci/config.yml",
        "**/azure-pipelines.yml",
    ]

    for pattern in cicd_patterns:
        for filepath in Path(target).glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for rule in CICD_RULES:
                            if re.search(rule["pattern"], line, re.IGNORECASE):
                                findings.append({
                                    "id": rule["id"],
                                    "name": rule["name"],
                                    "severity": rule["severity"],
                                    "file": str(filepath),
                                    "line": i,
                                    "content": line.strip()[:100],
                                    "description": rule["description"],
                                    "fix": rule["fix"],
                                })
            except IOError:
                continue

    return findings


def scan_gitignore(target: str) -> list:
    findings = []
    gitignore_path = Path(target) / ".gitignore"

    if not gitignore_path.exists():
        findings.append({
            "id": "CFG-GIT-001",
            "name": "Missing .gitignore",
            "severity": "high",
            "file": str(gitignore_path),
            "line": 0,
            "content": "No .gitignore file found",
            "description": "No .gitignore file — secrets and build artifacts may be committed",
            "fix": "Create a .gitignore file with entries for .env, *.key, *.pem, node_modules, etc.",
        })
        return findings

    try:
        with open(gitignore_path, "r", encoding="utf-8") as f:
            gitignore_content = f.read()

        for expected in [".env", "*.pem", "*.key"]:
            if expected not in gitignore_content:
                findings.append({
                    "id": "CFG-GIT-002",
                    "name": f"Missing gitignore: {expected}",
                    "severity": "medium",
                    "file": str(gitignore_path),
                    "line": 0,
                    "content": f"Pattern '{expected}' not in .gitignore",
                    "description": f"'{expected}' not in .gitignore — sensitive files may be committed",
                    "fix": f"Add '{expected}' to .gitignore",
                })
    except IOError:
        pass

    return findings


def scan_nginx_configs(target: str) -> list:
    findings = []
    nginx_patterns = ["**/nginx.conf", "**/nginx/*.conf", "**/conf.d/*.conf", "**/sites-available/*", "**/sites-enabled/*"]

    for pattern in nginx_patterns:
        for filepath in Path(target).glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for header, pattern_re in SECURITY_HEADERS_NGINX.items():
                    if not re.search(pattern_re, content):
                        findings.append({
                            "id": "CFG-NGX-001",
                            "name": f"Missing security header: {header}",
                            "severity": "medium",
                            "file": str(filepath),
                            "line": 0,
                            "content": f"Header '{header}' not configured",
                            "description": f"Security header '{header}' not set in nginx config",
                            "fix": f"Add: add_header {header} <value> always;",
                        })

                # Check for server_tokens
                if "server_tokens off" not in content and "server_tokens" not in content:
                    findings.append({
                        "id": "CFG-NGX-002",
                        "name": "Server version exposed",
                        "severity": "low",
                        "file": str(filepath),
                        "line": 0,
                        "content": "server_tokens not set to off",
                        "description": "Nginx version exposed in response headers",
                        "fix": "Add: server_tokens off;",
                    })

                # Check for TLS config
                if re.search(r"ssl_protocols.*(?:SSLv3|TLSv1(?:\.0)?(?:\s|;))", content):
                    findings.append({
                        "id": "CFG-NGX-003",
                        "name": "Weak TLS protocol enabled",
                        "severity": "high",
                        "file": str(filepath),
                        "line": 0,
                        "content": "SSLv3 or TLSv1.0 enabled",
                        "description": "Weak TLS protocols enabled — vulnerable to POODLE, BEAST attacks",
                        "fix": "Use: ssl_protocols TLSv1.2 TLSv1.3;",
                    })

            except IOError:
                continue

    return findings


def scan_exposed_secrets(target: str) -> list:
    """Check if secret files are present in the repository."""
    findings = []
    sensitive_patterns = [
        ("**/.env", "Environment file"),
        ("**/.env.production", "Production environment file"),
        ("**/id_rsa", "SSH private key"),
        ("**/id_ed25519", "SSH private key"),
        ("**/*.pem", "Certificate/key file"),
        ("**/credentials.json", "Credentials file"),
        ("**/service-account*.json", "Service account key"),
        ("**/.npmrc", "NPM config (may contain auth tokens)"),
        ("**/.pypirc", "PyPI config (may contain auth tokens)"),
    ]

    # Check if we're in a git repo
    git_dir = Path(target) / ".git"
    is_git = git_dir.exists()

    for pattern, desc in sensitive_patterns:
        for filepath in Path(target).glob(pattern):
            rel = filepath.relative_to(target)
            # Skip files inside hidden/vendor dirs
            parts = rel.parts
            if any(p in ("node_modules", ".git", "vendor", ".venv", "venv") for p in parts):
                continue

            findings.append({
                "id": "CFG-EXP-001",
                "name": f"Sensitive file present: {rel}",
                "severity": "high" if is_git else "medium",
                "file": str(filepath),
                "line": 0,
                "content": f"{desc} found at {rel}",
                "description": f"{desc} found in project directory" + (" — may be committed to git" if is_git else ""),
                "fix": f"Ensure {rel} is in .gitignore and not tracked in git history",
            })

    return findings


def format_markdown(findings: list, target: str) -> str:
    lines = [
        "# Configuration Security Audit Report",
        f"**Target:** {target}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
    ]

    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.extend([
        "## Summary",
        f"- **Total issues:** {len(findings)}",
    ])
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in severity_counts:
            lines.append(f"- **{sev.capitalize()}:** {severity_counts[sev]}")
    lines.append("")

    # Group by category
    categories = {}
    for f in findings:
        cat = f["id"].split("-")[1]
        cat_names = {"ENV": "Environment Variables", "DOC": "Docker", "CI": "CI/CD Pipeline",
                     "GIT": "Git Configuration", "NGX": "Nginx/Web Server", "EXP": "Exposed Secrets"}
        cat_name = cat_names.get(cat, "Other")
        if cat_name not in categories:
            categories[cat_name] = []
        categories[cat_name].append(f)

    for cat_name, cat_findings in categories.items():
        lines.append(f"## {cat_name}")
        lines.append("")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        cat_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
        for f in cat_findings:
            lines.extend([
                f"### [{f['severity'].upper()}] {f['name']}",
                f"- **File:** `{f['file']}:{f['line']}`",
                f"- **Detail:** {f['content']}",
                f"- **Description:** {f['description']}",
                f"- **Fix:** {f['fix']}",
                "",
            ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Configuration Security Auditor — scan configs, Docker, CI/CD for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target ./myproject
  %(prog)s --target . --format markdown --output config-report.md
        """
    )
    parser.add_argument("--target", required=True, help="Project directory to scan")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")

    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"Error: Target '{args.target}' is not a directory", file=sys.stderr)
        sys.exit(1)

    print("Scanning configuration files...", file=sys.stderr)

    all_findings = []
    all_findings.extend(scan_env_files(args.target))
    all_findings.extend(scan_dockerfiles(args.target))
    all_findings.extend(scan_cicd(args.target))
    all_findings.extend(scan_gitignore(args.target))
    all_findings.extend(scan_nginx_configs(args.target))
    all_findings.extend(scan_exposed_secrets(args.target))

    summary = {
        "total_issues": len(all_findings),
        "severity_breakdown": {},
        "scan_areas": ["env_files", "docker", "cicd", "gitignore", "nginx", "exposed_secrets"],
    }
    for f in all_findings:
        sev = f["severity"]
        summary["severity_breakdown"][sev] = summary["severity_breakdown"].get(sev, 0) + 1

    if args.format == "markdown":
        output = format_markdown(all_findings, args.target)
    else:
        output = json.dumps({"summary": summary, "findings": all_findings}, indent=2)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    print(f"\nTotal: {summary['total_issues']} configuration issues found", file=sys.stderr)


if __name__ == "__main__":
    main()
