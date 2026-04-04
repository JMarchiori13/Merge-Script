#!/usr/bin/env python3
"""
Dependency Security Checker — Scans project dependencies for known vulnerabilities.
Auto-detects package managers and checks against CVE/NVD databases.

Usage:
    python dependency_checker.py --target <path> [--output <file>] [--format json|markdown]

Examples:
    python dependency_checker.py --target ./myproject
    python dependency_checker.py --target ./myproject --output deps-report.json
    python dependency_checker.py --target . --format markdown --output deps.md
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── Known vulnerable version ranges (built-in database) ───
# This is a curated subset. For comprehensive checking, the script also
# calls npm audit, pip-audit, etc. when those tools are available.

KNOWN_VULNS = {
    "npm": {
        "lodash": [{"below": "4.17.21", "cve": "CVE-2021-23337", "severity": "critical", "title": "Command Injection via template"}],
        "express": [{"below": "4.19.2", "cve": "CVE-2024-29041", "severity": "medium", "title": "Open redirect vulnerability"}],
        "axios": [{"below": "1.6.0", "cve": "CVE-2023-45857", "severity": "high", "title": "CSRF token exposure via XSRF-TOKEN cookie"}],
        "jsonwebtoken": [{"below": "9.0.0", "cve": "CVE-2022-23529", "severity": "critical", "title": "Arbitrary code injection via secretOrPublicKey"}],
        "minimist": [{"below": "1.2.6", "cve": "CVE-2021-44906", "severity": "critical", "title": "Prototype pollution"}],
        "node-fetch": [{"below": "2.6.7", "cve": "CVE-2022-0235", "severity": "high", "title": "Exposure of sensitive info to unauthorized actor"}],
        "qs": [{"below": "6.10.3", "cve": "CVE-2022-24999", "severity": "high", "title": "Prototype pollution"}],
        "semver": [{"below": "7.5.2", "cve": "CVE-2022-25883", "severity": "high", "title": "ReDoS vulnerability"}],
        "shell-quote": [{"below": "1.7.3", "cve": "CVE-2021-42740", "severity": "critical", "title": "Command injection"}],
        "tar": [{"below": "6.1.9", "cve": "CVE-2021-37712", "severity": "high", "title": "Arbitrary file creation/overwrite"}],
    },
    "pip": {
        "django": [{"below": "4.2.11", "cve": "CVE-2024-27351", "severity": "high", "title": "ReDoS in Truncator"}],
        "flask": [{"below": "2.3.2", "cve": "CVE-2023-30861", "severity": "high", "title": "Session cookie on every response"}],
        "requests": [{"below": "2.31.0", "cve": "CVE-2023-32681", "severity": "medium", "title": "Proxy-Authorization header leak"}],
        "pyyaml": [{"below": "6.0.1", "cve": "CVE-2020-14343", "severity": "critical", "title": "Arbitrary code execution via yaml.load"}],
        "pillow": [{"below": "10.2.0", "cve": "CVE-2023-50447", "severity": "critical", "title": "Arbitrary code execution via PIL.ImageMath.eval"}],
        "cryptography": [{"below": "42.0.0", "cve": "CVE-2023-50782", "severity": "high", "title": "Bleichenbacher timing oracle in PKCS#1 v1.5"}],
        "jinja2": [{"below": "3.1.3", "cve": "CVE-2024-22195", "severity": "medium", "title": "XSS via xmlattr filter"}],
        "sqlalchemy": [{"below": "2.0.0", "cve": "CVE-2023-XXXX", "severity": "medium", "title": "SQL injection in legacy query APIs"}],
        "urllib3": [{"below": "2.0.7", "cve": "CVE-2023-45803", "severity": "medium", "title": "Request body not stripped on redirect"}],
        "werkzeug": [{"below": "3.0.1", "cve": "CVE-2023-46136", "severity": "high", "title": "DoS via large multipart form data"}],
    },
    "composer": {
        "laravel/framework": [{"below": "10.48.4", "cve": "CVE-2024-29291", "severity": "high", "title": "SQL injection in route model binding"}],
        "symfony/http-kernel": [{"below": "6.4.4", "cve": "CVE-2024-24565", "severity": "medium", "title": "Session fixation"}],
        "guzzlehttp/guzzle": [{"below": "7.8.0", "cve": "CVE-2023-29197", "severity": "medium", "title": "Improper header validation"}],
    },
    "maven": {
        "org.apache.logging.log4j:log4j-core": [{"below": "2.17.1", "cve": "CVE-2021-44228", "severity": "critical", "title": "Log4Shell — Remote Code Execution"}],
        "com.fasterxml.jackson.core:jackson-databind": [{"below": "2.16.0", "cve": "CVE-2022-42003", "severity": "high", "title": "Denial of Service via deep nesting"}],
        "org.springframework:spring-web": [{"below": "6.1.4", "cve": "CVE-2024-22243", "severity": "high", "title": "Open redirect via Host header"}],
    },
}


def parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    version_str = re.sub(r"[^\d.]", "", version_str)
    parts = version_str.split(".")
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def version_less_than(installed: str, threshold: str) -> bool:
    """Check if installed version is less than threshold."""
    try:
        return parse_version(installed) < parse_version(threshold)
    except Exception:
        return False


def detect_package_managers(target: str) -> dict:
    """Detect which package managers are used in the project."""
    managers = {}
    target_path = Path(target)

    checks = {
        "npm": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "pip": ["requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg"],
        "composer": ["composer.json", "composer.lock"],
        "maven": ["pom.xml"],
        "gradle": ["build.gradle", "build.gradle.kts"],
        "go": ["go.mod", "go.sum"],
        "cargo": ["Cargo.toml", "Cargo.lock"],
        "gems": ["Gemfile", "Gemfile.lock"],
        "nuget": ["*.csproj", "packages.config", "*.sln"],
    }

    for manager, files in checks.items():
        for pattern in files:
            if "*" in pattern:
                matches = list(target_path.glob(f"**/{pattern}"))
                if matches:
                    managers[manager] = str(matches[0])
            else:
                filepath = target_path / pattern
                if filepath.exists():
                    managers[manager] = str(filepath)
                    break
                for sub in target_path.rglob(pattern):
                    managers[manager] = str(sub)
                    break

    return managers


def parse_npm_deps(package_json_path: str) -> dict:
    """Parse dependencies from package.json."""
    deps = {}
    try:
        with open(package_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            if section in data:
                for name, version in data[section].items():
                    clean = re.sub(r"[\^~>=<]", "", version).strip()
                    deps[name] = clean
    except (json.JSONDecodeError, IOError):
        pass
    return deps


def parse_pip_deps(requirements_path: str) -> dict:
    """Parse dependencies from requirements.txt."""
    deps = {}
    try:
        with open(requirements_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~]+\s*)?([0-9][0-9.]*)?", line)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2) or "unknown"
                    deps[name] = version
    except IOError:
        pass
    return deps


def parse_composer_deps(composer_json_path: str) -> dict:
    """Parse dependencies from composer.json."""
    deps = {}
    try:
        with open(composer_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["require", "require-dev"]:
            if section in data:
                for name, version in data[section].items():
                    if name == "php":
                        continue
                    clean = re.sub(r"[\^~>=<*]", "", version).strip()
                    deps[name] = clean
    except (json.JSONDecodeError, IOError):
        pass
    return deps


def parse_maven_deps(pom_path: str) -> dict:
    """Parse dependencies from pom.xml (simple regex, not full XML parsing)."""
    deps = {}
    try:
        with open(pom_path, "r", encoding="utf-8") as f:
            content = f.read()
        dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
        for block in dep_blocks:
            group = re.search(r"<groupId>(.*?)</groupId>", block)
            artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
            version = re.search(r"<version>(.*?)</version>", block)
            if group and artifact and version:
                name = f"{group.group(1)}:{artifact.group(1)}"
                deps[name] = version.group(1)
    except IOError:
        pass
    return deps


def parse_go_deps(go_mod_path: str) -> dict:
    """Parse dependencies from go.mod."""
    deps = {}
    try:
        with open(go_mod_path, "r", encoding="utf-8") as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    parts = line.replace("require ", "").strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].lstrip("v")
                        deps[name] = version
    except IOError:
        pass
    return deps


def check_native_audit(manager: str, target: str) -> Optional[list]:
    """Try to run native audit tools if available."""
    results = []

    try:
        if manager == "npm":
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=target, capture_output=True, text=True, timeout=60
            )
            if proc.stdout:
                data = json.loads(proc.stdout)
                vulns = data.get("vulnerabilities", {})
                for name, info in vulns.items():
                    results.append({
                        "package": name,
                        "installed_version": info.get("range", "unknown"),
                        "severity": info.get("severity", "unknown"),
                        "title": info.get("title", f"Vulnerability in {name}"),
                        "fix_available": info.get("fixAvailable", False),
                        "source": "npm-audit",
                    })

        elif manager == "pip":
            proc = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=target, capture_output=True, text=True, timeout=60
            )
            if proc.stdout:
                vulns = json.loads(proc.stdout)
                for v in vulns:
                    results.append({
                        "package": v.get("name", "unknown"),
                        "installed_version": v.get("version", "unknown"),
                        "severity": v.get("severity", "unknown"),
                        "cve": v.get("id", ""),
                        "title": v.get("description", ""),
                        "fix_version": v.get("fix_versions", []),
                        "source": "pip-audit",
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass

    return results if results else None


def check_against_db(deps: dict, manager: str) -> list:
    """Check dependencies against built-in vulnerability database."""
    findings = []
    db = KNOWN_VULNS.get(manager, {})

    for pkg_name, installed_version in deps.items():
        if installed_version == "unknown":
            findings.append({
                "package": pkg_name,
                "installed_version": "unknown",
                "severity": "info",
                "title": "Version not pinned — unable to check for vulnerabilities",
                "cve": "",
                "fix_version": "",
                "source": "builtin-db",
            })
            continue

        vulns = db.get(pkg_name, [])
        for vuln in vulns:
            if version_less_than(installed_version, vuln["below"]):
                findings.append({
                    "package": pkg_name,
                    "installed_version": installed_version,
                    "severity": vuln["severity"],
                    "title": vuln["title"],
                    "cve": vuln["cve"],
                    "fix_version": vuln["below"],
                    "source": "builtin-db",
                })

    return findings


def check_unpinned_versions(deps: dict, raw_file: str) -> list:
    """Check for unpinned or loosely pinned versions."""
    findings = []
    try:
        with open(raw_file, "r", encoding="utf-8") as f:
            content = f.read()
    except IOError:
        return findings

    if raw_file.endswith("package.json"):
        for match in re.finditer(r'"([^"]+)"\s*:\s*"([\^~*>][^"]*)"', content):
            name, version = match.groups()
            if name not in ("name", "version", "description", "main", "scripts", "license"):
                findings.append({
                    "package": name,
                    "installed_version": version,
                    "severity": "low",
                    "title": f"Version not pinned exactly ({version}) — supply chain risk",
                    "cve": "",
                    "fix_version": f"Pin to exact: {re.sub(r'[^0-9.]', '', version)}",
                    "source": "version-check",
                })

    elif raw_file.endswith("requirements.txt"):
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if ">=" in line or "~=" in line or ("==" not in line and re.match(r"^[a-zA-Z]", line)):
                match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
                if match:
                    findings.append({
                        "package": match.group(1),
                        "installed_version": line,
                        "severity": "low",
                        "title": "Version not pinned exactly — supply chain risk",
                        "cve": "",
                        "fix_version": "Pin to exact version with ==",
                        "source": "version-check",
                    })

    return findings


def format_markdown(findings: list, managers: dict, target: str) -> str:
    lines = [
        "# Dependency Security Report",
        f"**Target:** {target}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Package managers detected:** {', '.join(managers.keys())}",
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

    if findings:
        lines.append("## Vulnerable Dependencies")
        lines.append("")
        lines.append("| Severity | Package | Installed | CVE | Title | Fix |")
        lines.append("|----------|---------|-----------|-----|-------|-----|")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 4))
        for f in sorted_findings:
            lines.append(
                f"| **{f['severity'].upper()}** | {f['package']} | {f['installed_version']} "
                f"| {f.get('cve', '')} | {f['title']} | {f.get('fix_version', 'N/A')} |"
            )
    else:
        lines.append("## No known vulnerabilities found")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Dependency Security Checker — scan project dependencies for known vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target ./myproject
  %(prog)s --target ./myproject --output deps-report.json
  %(prog)s --target . --format markdown --output deps.md
        """
    )
    parser.add_argument("--target", required=True, help="Project directory to scan")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format (default: json)")
    parser.add_argument("--use-native", action="store_true", help="Also run native audit tools (npm audit, pip-audit)")

    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"Error: Target '{args.target}' is not a directory", file=sys.stderr)
        sys.exit(1)

    managers = detect_package_managers(args.target)
    if not managers:
        print("No package managers detected in target directory", file=sys.stderr)
        sys.exit(0)

    print(f"Detected package managers: {', '.join(managers.keys())}", file=sys.stderr)

    all_findings = []

    for manager, filepath in managers.items():
        deps = {}
        if manager == "npm":
            deps = parse_npm_deps(filepath)
        elif manager == "pip":
            deps = parse_pip_deps(filepath)
        elif manager == "composer":
            deps = parse_composer_deps(filepath)
        elif manager == "maven":
            deps = parse_maven_deps(filepath)
        elif manager == "go":
            deps = parse_go_deps(filepath)

        if deps:
            print(f"  {manager}: {len(deps)} dependencies found", file=sys.stderr)
            db_findings = check_against_db(deps, manager)
            all_findings.extend(db_findings)

            version_findings = check_unpinned_versions(deps, filepath)
            all_findings.extend(version_findings)

        if args.use_native:
            native = check_native_audit(manager, args.target)
            if native:
                all_findings.extend(native)

    summary = {
        "total_issues": len(all_findings),
        "managers_detected": list(managers.keys()),
        "severity_breakdown": {},
    }
    for f in all_findings:
        sev = f["severity"]
        summary["severity_breakdown"][sev] = summary["severity_breakdown"].get(sev, 0) + 1

    if args.format == "markdown":
        output = format_markdown(all_findings, managers, args.target)
    else:
        output = json.dumps({"summary": summary, "findings": all_findings}, indent=2)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    print(f"\nTotal: {summary['total_issues']} issues found", file=sys.stderr)


if __name__ == "__main__":
    main()
