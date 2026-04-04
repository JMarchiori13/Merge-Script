#!/usr/bin/env python3
"""
Security Audit Report Generator — Aggregates findings from all scanners
into a unified professional audit report.

Usage:
    python report_generator.py --input <results-dir> --format markdown|json|pdf --output <path>
    python report_generator.py --input <results-dir> --check-threshold critical

Examples:
    python report_generator.py --input /tmp/pentest-results/ --format markdown --output /tmp/report.md
    python report_generator.py --input /tmp/pentest-results/ --format json --output /tmp/report.json
    python report_generator.py --input /tmp/pentest-results/ --check-threshold high  # CI/CD: fail if high+ vulns
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "[!]", "high": "[!]", "medium": "[~]", "low": "[-]", "info": "[i]"}


def load_results(input_dir: str) -> dict:
    """Load all scan result files from the input directory."""
    results = {
        "static": {"summary": {}, "findings": []},
        "dependencies": {"summary": {}, "findings": []},
        "config": {"summary": {}, "findings": []},
        "manual": [],
    }

    input_path = Path(input_dir)

    # Load JSON result files
    for json_file in input_path.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "static" in json_file.name.lower():
                results["static"] = data
            elif "dep" in json_file.name.lower():
                results["dependencies"] = data
            elif "config" in json_file.name.lower():
                results["config"] = data
            elif "manual" in json_file.name.lower():
                results["manual"] = data if isinstance(data, list) else data.get("findings", [])
            else:
                # Generic — merge findings
                findings = data.get("findings", [])
                if findings:
                    results["static"]["findings"].extend(findings)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load {json_file}: {e}", file=sys.stderr)

    return results


def aggregate_findings(results: dict) -> list:
    """Combine all findings into a single sorted list."""
    all_findings = []

    for source in ["static", "dependencies", "config"]:
        findings = results[source].get("findings", [])
        for f in findings:
            f["source"] = source
            all_findings.append(f)

    for f in results.get("manual", []):
        f["source"] = "manual"
        all_findings.append(f)

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 4))

    return all_findings


def compute_risk_score(findings: list) -> int:
    """Compute overall risk score (0-100)."""
    score = 0
    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical":
            score += 25
        elif sev == "high":
            score += 15
        elif sev == "medium":
            score += 5
        elif sev == "low":
            score += 1

    return min(100, score)


def generate_executive_summary(findings: list, risk_score: int) -> dict:
    """Generate executive summary data."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories = {}
    files_affected = set()

    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cat = f.get("category", f.get("source", "unknown"))
        categories[cat] = categories.get(cat, 0) + 1

        file_path = f.get("file", "")
        if file_path:
            files_affected.add(file_path)

    # Top 3 immediate actions
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    top_actions = []
    for cf in critical_findings[:3]:
        top_actions.append(f"Fix {cf.get('name', 'unknown')} in {cf.get('file', 'unknown')}")

    if not top_actions:
        high_findings = [f for f in findings if f.get("severity") == "high"]
        for hf in high_findings[:3]:
            top_actions.append(f"Address {hf.get('name', 'unknown')} in {hf.get('file', 'unknown')}")

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "categories": categories,
        "files_affected": len(files_affected),
        "risk_score": risk_score,
        "top_actions": top_actions,
    }


def format_markdown_report(findings: list, summary: dict, target: str) -> str:
    """Generate full Markdown audit report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# Security Audit Report",
        "",
        f"**Target:** `{target}`",
        f"**Date:** {now}",
        f"**Assessor:** Claude Security Pentest (Automated)",
        f"**Risk Score:** {summary['risk_score']}/100",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Total vulnerabilities found: **{summary['total_findings']}**",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {summary['severity_counts']['critical']} |",
        f"| High     | {summary['severity_counts']['high']} |",
        f"| Medium   | {summary['severity_counts']['medium']} |",
        f"| Low      | {summary['severity_counts']['low']} |",
        f"| Info     | {summary['severity_counts']['info']} |",
        "",
        f"**Files affected:** {summary['files_affected']}",
        "",
    ]

    if summary["top_actions"]:
        lines.append("### Immediate Actions Required")
        lines.append("")
        for i, action in enumerate(summary["top_actions"], 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    lines.extend(["---", "", "## Risk Score Methodology", "",
        "Risk score calculated using weighted severity model:",
        "- Critical: 25 points per finding",
        "- High: 15 points per finding",
        "- Medium: 5 points per finding",
        "- Low: 1 point per finding",
        "- Score capped at 100",
        "",
    ])

    # Group findings by severity
    lines.extend(["---", "", "## Detailed Findings", ""])

    finding_num = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = f.get("severity", "info")
        finding_num[sev] = finding_num.get(sev, 0) + 1
        prefix = sev.upper()
        num = finding_num[sev]
        fid = f.get("id", f"{prefix}-{num:03d}")

        lines.append(f"### [{prefix}-{num:03d}] {f.get('name', 'Unknown Vulnerability')}")
        lines.append("")
        lines.append(f"- **ID:** {fid}")
        lines.append(f"- **Severity:** {sev.upper()}")

        if "category" in f:
            lines.append(f"- **Category:** {f['category']}")
        if "cwe" in f:
            lines.append(f"- **CWE:** {f['cwe']}")
        if "cve" in f and f["cve"]:
            lines.append(f"- **CVE:** {f['cve']}")

        file_info = f.get("file", "N/A")
        line_num = f.get("line", "")
        if line_num:
            lines.append(f"- **Location:** `{file_info}:{line_num}`")
        else:
            lines.append(f"- **Location:** `{file_info}`")

        lines.append(f"- **Source:** {f.get('source', 'unknown')}")
        lines.append("")

        if "description" in f:
            lines.append(f"**Description:** {f['description']}")
            lines.append("")

        if "code" in f:
            lines.append("**Evidence:**")
            lines.append(f"```")
            lines.append(f"{f['code']}")
            lines.append(f"```")
            lines.append("")
        elif "content" in f:
            lines.append("**Evidence:**")
            lines.append(f"```")
            lines.append(f"{f['content']}")
            lines.append(f"```")
            lines.append("")

        if "fix" in f:
            lines.append(f"**Remediation:** {f['fix']}")
            lines.append("")
        if "fix_version" in f:
            lines.append(f"**Fix Version:** {f['fix_version']}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Recommendations summary
    lines.extend([
        "## Recommendations Summary",
        "",
        "### Priority 1 — Immediate (Critical)",
    ])
    critical = [f for f in findings if f.get("severity") == "critical"]
    if critical:
        for f in critical:
            lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
    else:
        lines.append("- No critical findings")
    lines.append("")

    lines.append("### Priority 2 — Short-term (High)")
    high = [f for f in findings if f.get("severity") == "high"]
    if high:
        for f in high:
            lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
    else:
        lines.append("- No high-severity findings")
    lines.append("")

    lines.append("### Priority 3 — Medium-term (Medium)")
    medium = [f for f in findings if f.get("severity") == "medium"]
    if medium:
        for f in medium:
            lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
    else:
        lines.append("- No medium-severity findings")
    lines.append("")

    lines.extend([
        "---",
        "",
        "## Appendix",
        "",
        "### Methodology",
        "This assessment was conducted using automated static analysis, dependency checking,",
        "configuration auditing, and manual code review. Tools used:",
        "- `static_analyzer.py` — Pattern-based code vulnerability scanner",
        "- `dependency_checker.py` — CVE/NVD dependency audit",
        "- `config_auditor.py` — Configuration and infrastructure security scanner",
        "- Manual code review for logic vulnerabilities",
        "",
        "### Severity Definitions",
        "| Severity | CVSS Range | Action Timeline |",
        "|----------|-----------|-----------------|",
        "| Critical | 9.0-10.0 | Fix immediately |",
        "| High | 7.0-8.9 | Fix within 7 days |",
        "| Medium | 4.0-6.9 | Fix within 30 days |",
        "| Low | 0.1-3.9 | Fix within 90 days |",
        "| Info | 0.0 | Consider in next sprint |",
        "",
        f"*Report generated on {now}*",
    ])

    return "\n".join(lines)


def format_json_report(findings: list, summary: dict, target: str) -> str:
    """Generate JSON audit report."""
    report = {
        "metadata": {
            "target": target,
            "date": datetime.now(timezone.utc).isoformat(),
            "assessor": "Claude Security Pentest (Automated)",
            "version": "1.0",
        },
        "executive_summary": summary,
        "findings": findings,
        "recommendations": {
            "critical": [f for f in findings if f.get("severity") == "critical"],
            "high": [f for f in findings if f.get("severity") == "high"],
            "medium": [f for f in findings if f.get("severity") == "medium"],
            "low": [f for f in findings if f.get("severity") == "low"],
        },
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def check_threshold(findings: list, threshold: str) -> bool:
    """Check if any findings meet or exceed the severity threshold. Returns True if threshold is breached."""
    threshold_level = SEVERITY_ORDER.get(threshold, 0)
    for f in findings:
        sev = f.get("severity", "info")
        if SEVERITY_ORDER.get(sev, 4) <= threshold_level:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Security Audit Report Generator — aggregate scan results into professional reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input /tmp/pentest-results/ --format markdown --output /tmp/report.md
  %(prog)s --input /tmp/pentest-results/ --format json --output /tmp/report.json
  %(prog)s --input /tmp/pentest-results/ --check-threshold critical  # CI/CD gate
        """
    )
    parser.add_argument("--input", required=True, help="Directory containing scan result JSON files")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--check-threshold", choices=["critical", "high", "medium", "low"],
                       help="CI/CD mode: exit with code 1 if findings at this severity or above exist")
    parser.add_argument("--target-name", default="", help="Project name for the report header")

    args = parser.parse_args()

    if not os.path.isdir(args.input):
        print(f"Error: Input directory '{args.input}' does not exist", file=sys.stderr)
        sys.exit(1)

    results = load_results(args.input)
    all_findings = aggregate_findings(results)
    risk_score = compute_risk_score(all_findings)
    summary = generate_executive_summary(all_findings, risk_score)

    target = args.target_name or args.input

    # CI/CD threshold check mode
    if args.check_threshold:
        breached = check_threshold(all_findings, args.check_threshold)
        if breached:
            sev_counts = summary["severity_counts"]
            print(f"SECURITY GATE FAILED: Found findings at {args.check_threshold} severity or above", file=sys.stderr)
            print(f"  Critical: {sev_counts['critical']}, High: {sev_counts['high']}, "
                  f"Medium: {sev_counts['medium']}, Low: {sev_counts['low']}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"SECURITY GATE PASSED: No findings at {args.check_threshold} severity or above", file=sys.stderr)
            sys.exit(0)

    # Generate report
    if args.format == "markdown":
        output = format_markdown_report(all_findings, summary, target)
    else:
        output = format_json_report(all_findings, summary, target)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)
        print(f"  Total findings: {summary['total_findings']}", file=sys.stderr)
        print(f"  Risk score: {risk_score}/100", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
