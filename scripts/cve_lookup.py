#!/usr/bin/env python3
"""
CVE Live Lookup — Queries the NVD (National Vulnerability Database) API in real-time
to check for known vulnerabilities in dependencies, instead of relying on a hardcoded list.

Usage:
    python cve_lookup.py --package <name> --version <version> [--ecosystem npm|pip|maven|go]
    python cve_lookup.py --cve <CVE-ID>
    python cve_lookup.py --scan-deps <path-to-project> [--output <file>]

Examples:
    python cve_lookup.py --package lodash --version 4.17.20 --ecosystem npm
    python cve_lookup.py --cve CVE-2021-44228
    python cve_lookup.py --scan-deps ./myproject --output cve-results.json

Note: NVD API has rate limits. Without an API key: 5 requests/30 seconds.
      With API key: 50 requests/30 seconds.
      Set NVD_API_KEY environment variable for higher rate limits.
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
from datetime import datetime, timezone
from pathlib import Path


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1"
RATE_LIMIT_DELAY = 6.5  # seconds between requests (no API key)
RATE_LIMIT_DELAY_KEYED = 0.7  # seconds with API key


def get_api_key():
    return os.environ.get("NVD_API_KEY", "")


def query_nvd(keyword=None, cve_id=None):
    """Query NVD API for CVEs."""
    api_key = get_api_key()

    if cve_id:
        url = f"{NVD_API_BASE}?cveId={cve_id}"
    elif keyword:
        url = f"{NVD_API_BASE}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=20"
    else:
        return None

    req = urllib.request.Request(url)
    req.add_header("User-Agent", "SecurityPentestSkill/1.0")
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        delay = RATE_LIMIT_DELAY_KEYED if api_key else RATE_LIMIT_DELAY
        time.sleep(delay)

        response = urllib.request.urlopen(req, timeout=30)
        data = json.loads(response.read().decode("utf-8"))
        return data
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  [!] NVD rate limit hit. Waiting 30s...", file=sys.stderr)
            time.sleep(30)
            try:
                response = urllib.request.urlopen(req, timeout=30)
                return json.loads(response.read().decode("utf-8"))
            except Exception:
                pass
        print(f"  [!] NVD API error: {e.code} {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] NVD API error: {e}", file=sys.stderr)
        return None


def query_osv(package, version, ecosystem):
    """Query OSV.dev API (Google's open source vulnerability database) — no rate limits."""
    eco_map = {
        "npm": "npm", "pip": "PyPI", "maven": "Maven",
        "go": "Go", "cargo": "crates.io", "gems": "RubyGems",
        "composer": "Packagist", "nuget": "NuGet",
    }

    osv_eco = eco_map.get(ecosystem, ecosystem)
    url = f"{OSV_API_BASE}/query"
    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": osv_eco}
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "SecurityPentestSkill/1.0")

    try:
        response = urllib.request.urlopen(req, timeout=20)
        data = json.loads(response.read().decode("utf-8"))
        return data
    except Exception as e:
        print(f"  [!] OSV API error: {e}", file=sys.stderr)
        return None


def parse_nvd_results(data):
    """Parse NVD API response into findings."""
    findings = []
    if not data or "vulnerabilities" not in data:
        return findings

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")

        metrics = cve.get("metrics", {})
        cvss_score = 0
        severity = "info"

        # Try CVSS 3.1 first, then 3.0, then 2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0)
                if cvss_score >= 9.0: severity = "critical"
                elif cvss_score >= 7.0: severity = "high"
                elif cvss_score >= 4.0: severity = "medium"
                elif cvss_score > 0: severity = "low"
                break

        references = [r.get("url", "") for r in cve.get("references", [])[:3]]

        findings.append({
            "cve_id": cve_id,
            "description": desc[:500],
            "cvss_score": cvss_score,
            "severity": severity,
            "references": references,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        })

    return findings


def parse_osv_results(data):
    """Parse OSV API response into findings."""
    findings = []
    if not data or "vulns" not in data:
        return findings

    for vuln in data.get("vulns", []):
        vuln_id = vuln.get("id", "")
        summary = vuln.get("summary", "No summary")
        details = vuln.get("details", "")
        severity_list = vuln.get("severity", [])

        cvss_score = 0
        severity = "info"
        for s in severity_list:
            if s.get("type") == "CVSS_V3":
                score_str = s.get("score", "")
                # Extract base score from CVSS vector
                match = re.search(r"CVSS:3\.[01]/.*", score_str)
                if match:
                    # Simple severity from score
                    pass

        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]

        # Get severity from database_specific if available
        db_specific = vuln.get("database_specific", {})
        osv_severity = db_specific.get("severity", "").upper()
        if osv_severity == "CRITICAL": severity = "critical"
        elif osv_severity == "HIGH": severity = "high"
        elif osv_severity == "MODERATE" or osv_severity == "MEDIUM": severity = "medium"
        elif osv_severity == "LOW": severity = "low"

        # Get affected version ranges
        affected = vuln.get("affected", [])
        fix_version = ""
        for aff in affected:
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fix_version = event["fixed"]

        references = [r.get("url", "") for r in vuln.get("references", [])[:3]]

        findings.append({
            "cve_id": cve_ids[0] if cve_ids else vuln_id,
            "osv_id": vuln_id,
            "description": summary[:500],
            "details": details[:300],
            "cvss_score": cvss_score,
            "severity": severity,
            "fix_version": fix_version,
            "references": references,
            "published": vuln.get("published", ""),
        })

    return findings


def lookup_package(package, version, ecosystem):
    """Look up vulnerabilities for a specific package version."""
    print(f"  Checking {ecosystem}/{package}@{version}...", file=sys.stderr)

    all_findings = []

    # Query OSV first (faster, no rate limits)
    osv_data = query_osv(package, version, ecosystem)
    if osv_data:
        osv_findings = parse_osv_results(osv_data)
        for f in osv_findings:
            f["source"] = "osv"
            f["package"] = package
            f["version"] = version
            f["ecosystem"] = ecosystem
        all_findings.extend(osv_findings)

    # If no OSV results, try NVD
    if not all_findings:
        nvd_data = query_nvd(keyword=f"{package} {version}")
        if nvd_data:
            nvd_findings = parse_nvd_results(nvd_data)
            for f in nvd_findings:
                f["source"] = "nvd"
                f["package"] = package
                f["version"] = version
                f["ecosystem"] = ecosystem
            all_findings.extend(nvd_findings)

    return all_findings


def lookup_cve(cve_id):
    """Look up a specific CVE by ID."""
    print(f"  Looking up {cve_id}...", file=sys.stderr)
    data = query_nvd(cve_id=cve_id)
    if data:
        return parse_nvd_results(data)
    return []


def parse_deps_from_project(target):
    """Parse dependencies from project files."""
    deps = []
    target_path = Path(target)

    # package.json (npm)
    pkg_json = target_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            for section in ["dependencies", "devDependencies"]:
                for name, ver in data.get(section, {}).items():
                    clean = re.sub(r"[\^~>=<]", "", ver).strip()
                    deps.append({"name": name, "version": clean, "ecosystem": "npm"})
        except Exception:
            pass

    # requirements.txt (pip)
    req_txt = target_path / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:==|>=|~=|<=)?\s*([0-9][0-9.]*)?", line)
                if match:
                    deps.append({
                        "name": match.group(1).lower(),
                        "version": match.group(2) or "latest",
                        "ecosystem": "pip",
                    })
        except Exception:
            pass

    # go.mod
    go_mod = target_path / "go.mod"
    if go_mod.exists():
        try:
            content = go_mod.read_text(encoding="utf-8")
            for match in re.finditer(r"^\s+([\w./-]+)\s+v([\d.]+)", content, re.MULTILINE):
                deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "go"})
        except Exception:
            pass

    # composer.json
    comp_json = target_path / "composer.json"
    if comp_json.exists():
        try:
            data = json.loads(comp_json.read_text(encoding="utf-8"))
            for section in ["require", "require-dev"]:
                for name, ver in data.get(section, {}).items():
                    if name == "php":
                        continue
                    clean = re.sub(r"[\^~>=<*]", "", ver).strip()
                    deps.append({"name": name, "version": clean, "ecosystem": "composer"})
        except Exception:
            pass

    return deps


def format_markdown(findings, target):
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    lines = [
        "# Live CVE Lookup Report",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Total vulnerabilities:** {len(findings)}",
        f"**Critical:** {sev_counts['critical']} | **High:** {sev_counts['high']} | "
        f"**Medium:** {sev_counts['medium']} | **Low:** {sev_counts['low']}",
        "", "---", "",
    ]

    if findings:
        lines.extend(["| Severity | CVE | Package | Version | Fix | Description |",
                      "|-|-|-|-|-|-|"])
        for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),4)):
            lines.append(
                f"| **{f['severity'].upper()}** | {f.get('cve_id','')} | "
                f"{f.get('package','')} | {f.get('version','')} | "
                f"{f.get('fix_version','N/A')} | {f.get('description','')[:80]}... |"
            )
    else:
        lines.append("No known vulnerabilities found.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="CVE Live Lookup — query NVD and OSV APIs for real-time vulnerability data",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--package", help="Package name to check")
    group.add_argument("--cve", help="Specific CVE ID to look up")
    group.add_argument("--scan-deps", help="Project path to scan all dependencies")

    parser.add_argument("--version", help="Package version (with --package)")
    parser.add_argument("--ecosystem", choices=["npm", "pip", "maven", "go", "cargo", "gems", "composer", "nuget"],
                       help="Package ecosystem (with --package)")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")

    args = parser.parse_args()

    findings = []

    if args.package:
        if not args.version:
            parser.error("--version is required with --package")
        if not args.ecosystem:
            parser.error("--ecosystem is required with --package")
        findings = lookup_package(args.package, args.version, args.ecosystem)
        target = f"{args.ecosystem}/{args.package}@{args.version}"

    elif args.cve:
        findings = lookup_cve(args.cve)
        target = args.cve

    elif args.scan_deps:
        if not os.path.isdir(args.scan_deps):
            print(f"Error: '{args.scan_deps}' is not a directory", file=sys.stderr)
            sys.exit(1)
        deps = parse_deps_from_project(args.scan_deps)
        print(f"[*] Found {len(deps)} dependencies to check", file=sys.stderr)
        for dep in deps:
            dep_findings = lookup_package(dep["name"], dep["version"], dep["ecosystem"])
            findings.extend(dep_findings)
        target = args.scan_deps

    print(f"\n[*] Total vulnerabilities found: {len(findings)}", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(findings, target)
    else:
        output = json.dumps({"findings": findings, "total": len(findings),
                            "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2, default=str)

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
