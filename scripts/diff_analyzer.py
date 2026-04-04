#!/usr/bin/env python3
"""
Security Diff Analyzer — Compares security reports between code versions to identify
new, resolved, and persistent vulnerabilities.

Usage:
    python diff_analyzer.py --baseline <old-report.json> --current <new-report.json> [--output <file>] [--format json|markdown]
    python diff_analyzer.py --baseline-dir <old-results/> --current-dir <new-results/> [--output <file>]

Examples:
    python diff_analyzer.py --baseline v1-report.json --current v2-report.json --format markdown
    python diff_analyzer.py --baseline-dir results-v1/ --current-dir results-v2/ --output diff.md
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_report(path: str) -> dict:
    """Load a security report JSON file or directory of JSON files."""
    if os.path.isdir(path):
        all_findings = []
        for json_file in Path(path).glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                findings = data.get("findings", [])
                all_findings.extend(findings)
            except (json.JSONDecodeError, IOError):
                continue
        return {"findings": all_findings}
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "findings" not in data:
                # Maybe it's a direct list
                if isinstance(data, list):
                    return {"findings": data}
                return {"findings": []}
            return data
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading {path}: {e}", file=sys.stderr)
            return {"findings": []}


def fingerprint_finding(finding: dict) -> str:
    """Create a unique fingerprint for a finding to track it across versions."""
    components = [
        finding.get("id", ""),
        finding.get("name", ""),
        finding.get("file", ""),
        str(finding.get("cwe", "")),
        finding.get("category", ""),
    ]
    return "|".join(components).lower()


def fingerprint_finding_flexible(finding: dict) -> str:
    """Create a flexible fingerprint (ignoring line numbers and exact file path)."""
    name = finding.get("name", "")
    cwe = str(finding.get("cwe", ""))
    category = finding.get("category", "")
    # Use just the filename, not full path
    filepath = finding.get("file", "")
    filename = os.path.basename(filepath) if filepath else ""
    return f"{name}|{filename}|{cwe}|{category}".lower()


def compare_reports(baseline: dict, current: dict) -> dict:
    """Compare two security reports and categorize findings."""
    baseline_findings = baseline.get("findings", [])
    current_findings = current.get("findings", [])

    # Create fingerprint sets
    baseline_exact = {}
    baseline_flexible = {}
    for f in baseline_findings:
        fp_exact = fingerprint_finding(f)
        fp_flex = fingerprint_finding_flexible(f)
        baseline_exact[fp_exact] = f
        if fp_flex not in baseline_flexible:
            baseline_flexible[fp_flex] = []
        baseline_flexible[fp_flex].append(f)

    current_exact = {}
    current_flexible = {}
    for f in current_findings:
        fp_exact = fingerprint_finding(f)
        fp_flex = fingerprint_finding_flexible(f)
        current_exact[fp_exact] = f
        if fp_flex not in current_flexible:
            current_flexible[fp_flex] = []
        current_flexible[fp_flex].append(f)

    new_findings = []
    resolved_findings = []
    persistent_findings = []
    moved_findings = []

    # Find new and persistent findings
    for fp, finding in current_exact.items():
        if fp in baseline_exact:
            persistent_findings.append(finding)
        else:
            fp_flex = fingerprint_finding_flexible(finding)
            if fp_flex in baseline_flexible:
                moved_findings.append({
                    "current": finding,
                    "previous": baseline_flexible[fp_flex][0],
                    "change": "moved/modified",
                })
            else:
                new_findings.append(finding)

    # Find resolved findings
    for fp, finding in baseline_exact.items():
        if fp not in current_exact:
            fp_flex = fingerprint_finding_flexible(finding)
            if fp_flex not in current_flexible:
                resolved_findings.append(finding)

    # Severity analysis
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def count_by_severity(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # Risk score delta
    def risk_score(findings):
        score = 0
        for f in findings:
            sev = f.get("severity", "info")
            if sev == "critical": score += 25
            elif sev == "high": score += 15
            elif sev == "medium": score += 5
            elif sev == "low": score += 1
        return min(100, score)

    baseline_score = risk_score(baseline_findings)
    current_score = risk_score(current_findings)

    result = {
        "summary": {
            "baseline_total": len(baseline_findings),
            "current_total": len(current_findings),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "persistent_findings": len(persistent_findings),
            "moved_findings": len(moved_findings),
            "baseline_risk_score": baseline_score,
            "current_risk_score": current_score,
            "risk_delta": current_score - baseline_score,
            "trend": "improved" if current_score < baseline_score else ("degraded" if current_score > baseline_score else "unchanged"),
            "new_by_severity": count_by_severity(new_findings),
            "resolved_by_severity": count_by_severity(resolved_findings),
        },
        "new_findings": sorted(new_findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4)),
        "resolved_findings": sorted(resolved_findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4)),
        "persistent_findings": sorted(persistent_findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4)),
        "moved_findings": moved_findings,
    }

    return result


def format_markdown(diff: dict, baseline_path: str, current_path: str) -> str:
    summary = diff["summary"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    trend_indicator = {"improved": "IMPROVED", "degraded": "DEGRADED", "unchanged": "UNCHANGED"}
    trend = trend_indicator.get(summary["trend"], "UNKNOWN")

    lines = [
        "# Security Diff Report",
        "",
        f"**Date:** {now}",
        f"**Baseline:** `{baseline_path}`",
        f"**Current:** `{current_path}`",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Baseline | Current | Delta |",
        f"|--------|----------|---------|-------|",
        f"| Total Findings | {summary['baseline_total']} | {summary['current_total']} | {summary['current_total'] - summary['baseline_total']:+d} |",
        f"| Risk Score | {summary['baseline_risk_score']}/100 | {summary['current_risk_score']}/100 | {summary['risk_delta']:+d} |",
        f"| Trend | | **{trend}** | |",
        "",
        f"- **New vulnerabilities:** {summary['new_findings']}",
        f"- **Resolved vulnerabilities:** {summary['resolved_findings']}",
        f"- **Persistent vulnerabilities:** {summary['persistent_findings']}",
        f"- **Moved/modified:** {summary['moved_findings']}",
        "",
    ]

    # New findings severity breakdown
    new_sev = summary["new_by_severity"]
    if summary["new_findings"] > 0:
        lines.append("### New Vulnerabilities by Severity")
        lines.append(f"Critical: {new_sev['critical']} | High: {new_sev['high']} | Medium: {new_sev['medium']} | Low: {new_sev['low']}")
        lines.append("")

    # Resolved findings severity breakdown
    res_sev = summary["resolved_by_severity"]
    if summary["resolved_findings"] > 0:
        lines.append("### Resolved Vulnerabilities by Severity")
        lines.append(f"Critical: {res_sev['critical']} | High: {res_sev['high']} | Medium: {res_sev['medium']} | Low: {res_sev['low']}")
        lines.append("")

    lines.extend(["---", ""])

    # New findings detail
    if diff["new_findings"]:
        lines.append("## NEW Vulnerabilities (introduced in current version)")
        lines.append("")
        for f in diff["new_findings"]:
            sev = f.get("severity", "info").upper()
            lines.append(f"### [{sev}] {f.get('name', 'Unknown')}")
            lines.append(f"- **ID:** {f.get('id', 'N/A')}")
            if f.get("file"):
                lines.append(f"- **Location:** `{f['file']}:{f.get('line', '')}`")
            if f.get("category"):
                lines.append(f"- **Category:** {f['category']}")
            if f.get("description"):
                lines.append(f"- **Description:** {f['description']}")
            if f.get("fix"):
                lines.append(f"- **Fix:** {f['fix']}")
            lines.append("")

    # Resolved findings
    if diff["resolved_findings"]:
        lines.append("## RESOLVED Vulnerabilities (fixed in current version)")
        lines.append("")
        for f in diff["resolved_findings"]:
            sev = f.get("severity", "info").upper()
            lines.append(f"- [{sev}] **{f.get('name', 'Unknown')}** — `{f.get('file', 'N/A')}` *(resolved)*")
        lines.append("")

    # Persistent findings
    if diff["persistent_findings"]:
        lines.append("## PERSISTENT Vulnerabilities (still present)")
        lines.append("")
        lines.append("| Severity | Name | Location |")
        lines.append("|----------|------|----------|")
        for f in diff["persistent_findings"]:
            lines.append(f"| {f.get('severity', 'info').upper()} | {f.get('name', 'Unknown')} | `{f.get('file', 'N/A')}:{f.get('line', '')}` |")
        lines.append("")

    # Moved findings
    if diff["moved_findings"]:
        lines.append("## MOVED/MODIFIED Vulnerabilities")
        lines.append("")
        for m in diff["moved_findings"]:
            curr = m["current"]
            prev = m["previous"]
            lines.append(f"- **{curr.get('name', 'Unknown')}**: moved from `{prev.get('file', 'N/A')}:{prev.get('line', '')}` to `{curr.get('file', 'N/A')}:{curr.get('line', '')}`")
        lines.append("")

    # Action items
    lines.extend([
        "---",
        "",
        "## Action Items",
        "",
    ])

    if diff["new_findings"]:
        new_critical = [f for f in diff["new_findings"] if f.get("severity") == "critical"]
        new_high = [f for f in diff["new_findings"] if f.get("severity") == "high"]
        if new_critical:
            lines.append("### URGENT — New Critical Vulnerabilities")
            for f in new_critical:
                lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
            lines.append("")
        if new_high:
            lines.append("### HIGH PRIORITY — New High Vulnerabilities")
            for f in new_high:
                lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
            lines.append("")

    if diff["persistent_findings"]:
        persistent_critical = [f for f in diff["persistent_findings"] if f.get("severity") in ("critical", "high")]
        if persistent_critical:
            lines.append("### OVERDUE — Persistent Critical/High Vulnerabilities")
            for f in persistent_critical:
                lines.append(f"- [ ] Fix **{f.get('name', '')}** in `{f.get('file', '')}`")
            lines.append("")

    if diff["resolved_findings"]:
        lines.append(f"### Congratulations — {len(diff['resolved_findings'])} vulnerabilities resolved!")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Security Diff Analyzer — compare security reports between code versions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --baseline v1-report.json --current v2-report.json --format markdown
  %(prog)s --baseline-dir results-v1/ --current-dir results-v2/ --output diff.md
        """
    )
    group = parser.add_argument_group("Report files")
    group.add_argument("--baseline", help="Baseline report JSON file")
    group.add_argument("--current", help="Current report JSON file")

    group2 = parser.add_argument_group("Report directories")
    group2.add_argument("--baseline-dir", help="Directory containing baseline scan results")
    group2.add_argument("--current-dir", help="Directory containing current scan results")

    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")

    args = parser.parse_args()

    baseline_path = args.baseline or args.baseline_dir
    current_path = args.current or args.current_dir

    if not baseline_path or not current_path:
        parser.error("Must provide either --baseline/--current or --baseline-dir/--current-dir")

    if not os.path.exists(baseline_path):
        print(f"Error: Baseline '{baseline_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(current_path):
        print(f"Error: Current '{current_path}' does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Loading baseline: {baseline_path}", file=sys.stderr)
    baseline = load_report(baseline_path)
    print(f"  {len(baseline['findings'])} findings", file=sys.stderr)

    print(f"Loading current: {current_path}", file=sys.stderr)
    current = load_report(current_path)
    print(f"  {len(current['findings'])} findings", file=sys.stderr)

    diff = compare_reports(baseline, current)

    summary = diff["summary"]
    print(f"\nComparison result:", file=sys.stderr)
    print(f"  New: {summary['new_findings']} | Resolved: {summary['resolved_findings']} | Persistent: {summary['persistent_findings']}", file=sys.stderr)
    print(f"  Risk: {summary['baseline_risk_score']} → {summary['current_risk_score']} ({summary['risk_delta']:+d}) [{summary['trend'].upper()}]", file=sys.stderr)

    if args.format == "markdown":
        output = format_markdown(diff, baseline_path, current_path)
    else:
        output = json.dumps(diff, indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\nDiff report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
