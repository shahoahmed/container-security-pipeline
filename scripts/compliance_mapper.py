#!/usr/bin/env python3
"""
compliance_mapper.py

Parses Trivy container scan output and maps each vulnerability finding to the
NIST SP 800-171 control family it falls under, producing an audit-ready
report. Also acts as the CI/CD security gate: returns a non-zero exit code
if findings at or above the configured severity threshold are present.

This automates the manual mapping work of tying technical findings to
specific control requirements (DFARS 252.204-7012 / NIST 800-171) for
federal audit readiness.

Usage:
    python compliance_mapper.py --input trivy-results.json --output reports/
    python compliance_mapper.py --input trivy-results.json --gate-only --fail-on CRITICAL,HIGH
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# NIST SP 800-171 control mapping
#
# Every finding gets the baseline controls (vulnerability scanning + flaw
# remediation apply to any flagged CVE). Severity and keyword matches in the
# finding's title/description layer on additional, more specific controls.
# This mirrors how a real compliance mapping exercise works: start broad,
# narrow based on what the finding actually touches.
# ---------------------------------------------------------------------------

BASELINE_CONTROLS = [
    "3.11.2 - Periodically scan for vulnerabilities",
    "3.14.1 - Identify, report, and correct system flaws in a timely manner",
]

SEVERITY_CONTROLS = {
    "CRITICAL": [
        "3.4.2 - Establish and enforce security configuration settings",
        "3.11.3 - Remediate vulnerabilities in accordance with risk assessments",
    ],
    "HIGH": [
        "3.11.3 - Remediate vulnerabilities in accordance with risk assessments",
    ],
    "MEDIUM": [],
    "LOW": [],
}

KEYWORD_CONTROLS = {
    "auth": ["3.5.1 - Identify and authenticate organizational users"],
    "privilege": ["3.1.5 - Employ the principle of least privilege"],
    "crypto": ["3.13.11 - Employ FIPS-validated cryptography"],
    "tls": ["3.13.8 - Implement cryptographic mechanisms to protect CUI in transit"],
    "ssl": ["3.13.8 - Implement cryptographic mechanisms to protect CUI in transit"],
    "denial of service": ["3.13.1 - Monitor, control, and protect organizational communications"],
    "buffer overflow": ["3.13.1 - Monitor, control, and protect organizational communications"],
    "remote code execution": ["3.13.1 - Monitor, control, and protect organizational communications"],
}

# Simple weighted risk score, useful as a single trend metric across builds
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def load_trivy_results(path):
    with open(path, "r") as f:
        data = json.load(f)
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion", "unknown"),
                "fixed_version": vuln.get("FixedVersion", "not available"),
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "url": vuln.get("PrimaryURL", ""),
                "target": target,
            })
    return findings


def map_controls(finding):
    """Return the deduplicated list of NIST 800-171 controls a finding maps to."""
    controls = set(BASELINE_CONTROLS)
    controls.update(SEVERITY_CONTROLS.get(finding["severity"], []))

    haystack = f"{finding['title']} {finding['description']}".lower()
    for keyword, mapped in KEYWORD_CONTROLS.items():
        if keyword in haystack:
            controls.update(mapped)

    return sorted(controls)


def build_report(findings, image_name):
    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    risk_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    fixable = sum(1 for f in findings if f["fixed_version"] not in ("not available", "unknown", ""))

    control_coverage = defaultdict(int)
    for f in findings:
        for c in map_controls(f):
            control_coverage[c] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "image": image_name,
        "total_findings": len(findings),
        "by_severity": {sev: len(items) for sev, items in by_severity.items()},
        "fixable_findings": fixable,
        "risk_score": risk_score,
        "control_coverage": dict(sorted(control_coverage.items(), key=lambda x: -x[1])),
        "findings": [
            {**f, "mapped_controls": map_controls(f)} for f in findings
        ],
    }


def render_markdown(report):
    lines = []
    lines.append(f"# Container Compliance Report")
    lines.append("")
    lines.append(f"**Image:** `{report['image']}`  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Standard:** NIST SP 800-171 / DFARS 252.204-7012")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = report["by_severity"].get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")
    lines.append("")
    lines.append(f"**Total findings:** {report['total_findings']}  ")
    lines.append(f"**Fixable (patch available):** {report['fixable_findings']}  ")
    lines.append(f"**Weighted risk score:** {report['risk_score']}")
    lines.append("")
    lines.append("## NIST 800-171 Control Coverage")
    lines.append("")
    lines.append("Controls touched by at least one finding in this scan, ordered by how many findings map to each:")
    lines.append("")
    lines.append("| Control | Findings mapped |")
    lines.append("|---|---|")
    for control, count in report["control_coverage"].items():
        lines.append(f"| {control} | {count} |")
    lines.append("")
    lines.append("## Findings Detail")
    lines.append("")
    lines.append("| CVE | Package | Severity | Installed | Fixed In | Mapped Controls |")
    lines.append("|---|---|---|---|---|---|")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for f in sorted(report["findings"], key=lambda x: sev_order.get(x["severity"], 5)):
        controls_short = "<br>".join(c.split(" - ")[0] for c in f["mapped_controls"])
        lines.append(
            f"| {f['id']} | {f['package']} | {f['severity']} | "
            f"{f['installed_version']} | {f['fixed_version']} | {controls_short} |"
        )
    lines.append("")
    return "\n".join(lines)


def gate_check(findings, fail_on):
    fail_on = set(s.strip().upper() for s in fail_on.split(","))
    blocking = [f for f in findings if f["severity"] in fail_on]
    return blocking


def main():
    parser = argparse.ArgumentParser(description="Map Trivy scan results to NIST 800-171 controls")
    parser.add_argument("--input", required=True, help="Path to Trivy JSON output")
    parser.add_argument("--output", help="Directory to write reports to")
    parser.add_argument("--image", default="unknown", help="Image name/tag being reported on")
    parser.add_argument("--gate-only", action="store_true", help="Only run the pass/fail gate, skip report generation")
    parser.add_argument("--fail-on", default="CRITICAL,HIGH", help="Comma-separated severities that fail the build")
    args = parser.parse_args()

    findings = load_trivy_results(args.input)

    if args.gate_only:
        blocking = gate_check(findings, args.fail_on)
        if blocking:
            print(f"SECURITY GATE: FAILED — {len(blocking)} finding(s) at or above threshold ({args.fail_on})")
            for f in blocking:
                print(f"  [{f['severity']}] {f['id']} in {f['package']} ({f['installed_version']})")
            sys.exit(1)
        else:
            print(f"SECURITY GATE: PASSED — no findings at or above threshold ({args.fail_on})")
            sys.exit(0)

    report = build_report(findings, args.image)

    out_dir = Path(args.output or ".")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "compliance-report.json"
    md_path = out_dir / "compliance-report.md"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(md_path, "w") as f:
        f.write(render_markdown(report))

    print(f"Report written to {json_path} and {md_path}")
    print(f"Total findings: {report['total_findings']} | Risk score: {report['risk_score']}")
    for sev, count in report["by_severity"].items():
        print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
