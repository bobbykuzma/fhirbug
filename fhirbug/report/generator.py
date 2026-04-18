"""Report generation — JSON and HTML output."""

from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from fhirbug.core.models import ScanResult, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_HTML_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#0891b2",
    "info": "#6b7280",
}


def print_summary(result: ScanResult) -> None:
    """Print a rich summary table of findings to the console."""
    if not result.findings:
        console.print("\n[green bold]No findings.[/]")
        return

    console.print(f"\n[bold]{'='*60}[/]")
    console.print(f"[bold]SCAN RESULTS: {result.target}[/]")
    console.print(f"[bold]{'='*60}[/]")

    # Summary counts
    summary = Table(title="Findings Summary", show_header=True)
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")
    for sev in Severity:
        count = len([f for f in result.findings if f.severity == sev])
        if count > 0:
            summary.add_row(
                f"[{SEVERITY_COLORS[sev]}]{sev.value.upper()}[/]",
                str(count),
            )
    console.print(summary)

    # Detailed findings
    console.print(f"\n[bold]Detailed Findings ({len(result.findings)} total):[/]\n")

    for i, finding in enumerate(
        sorted(result.findings, key=lambda f: list(Severity).index(f.severity)),
        1,
    ):
        sev_style = SEVERITY_COLORS[finding.severity]
        console.print(
            f"  [{sev_style}][{finding.severity.value.upper()}][/] "
            f"#{i}: {finding.title}"
        )
        console.print(f"    Category: {finding.category.value}")
        console.print(f"    Endpoint: {finding.endpoint}")
        console.print(f"    {finding.description}")
        if finding.remediation:
            console.print(f"    [green]Remediation:[/] {finding.remediation}")
        console.print()

    if result.errors:
        console.print(f"\n[yellow]Errors ({len(result.errors)}):[/]")
        for err in result.errors:
            console.print(f"  - {err}")


def save_json(result: ScanResult, path: str) -> None:
    """Save findings as JSON."""
    output = Path(path)
    output.write_text(result.to_json())
    console.print(f"\n[green]JSON report saved to:[/] {output}")


def save_html(result: ScanResult, path: str) -> None:
    """Save findings as a standalone HTML report."""
    findings_html = []
    for i, finding in enumerate(
        sorted(result.findings, key=lambda f: list(Severity).index(f.severity)),
        1,
    ):
        sev = finding.severity.value
        color = SEVERITY_HTML_COLORS.get(sev, "#6b7280")
        evidence_json = html.escape(json.dumps(finding.evidence, indent=2))

        findings_html.append(f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity" style="background:{color}">{sev.upper()}</span>
                <span class="title">#{i}: {html.escape(finding.title)}</span>
            </div>
            <div class="finding-body">
                <p><strong>Category:</strong> {html.escape(finding.category.value)}</p>
                <p><strong>Endpoint:</strong> <code>{html.escape(finding.endpoint)}</code></p>
                <p>{html.escape(finding.description)}</p>
                {"<p><strong>Remediation:</strong> " + html.escape(finding.remediation) + "</p>" if finding.remediation else ""}
                <details>
                    <summary>Evidence</summary>
                    <pre>{evidence_json}</pre>
                </details>
            </div>
        </div>
        """)

    counts = {
        sev.value: len([f for f in result.findings if f.severity == sev])
        for sev in Severity
    }
    summary_items = "".join(
        f'<span class="severity" style="background:{SEVERITY_HTML_COLORS[s]}">'
        f'{s.upper()}: {c}</span> '
        for s, c in counts.items() if c > 0
    )

    ep_info = result.endpoint_info
    ep_section = ""
    if ep_info:
        ep_section = f"""
        <div class="section">
            <h2>Target Information</h2>
            <table>
                <tr><td>Base URL</td><td><code>{html.escape(ep_info.base_url)}</code></td></tr>
                <tr><td>FHIR Version</td><td>{html.escape(ep_info.fhir_version)}</td></tr>
                <tr><td>Software</td><td>{html.escape(ep_info.software_name)} {html.escape(ep_info.software_version)}</td></tr>
                <tr><td>Vendor</td><td>{html.escape(ep_info.vendor or "unknown")}</td></tr>
                <tr><td>Resources</td><td>{len(ep_info.supported_resources)}</td></tr>
                <tr><td>Operations</td><td>{html.escape(", ".join(ep_info.operations) or "none")}</td></tr>
            </table>
        </div>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FHIR Security Scan: {html.escape(result.target)}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           max-width: 960px; margin: 40px auto; padding: 0 20px;
           background: #0f172a; color: #e2e8f0; }}
    h1 {{ color: #f1f5f9; border-bottom: 2px solid #334155; padding-bottom: 12px; }}
    h2 {{ color: #94a3b8; }}
    .summary {{ margin: 20px 0; }}
    .severity {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
                 color: white; font-size: 0.8em; font-weight: 700; margin-right: 6px; }}
    .finding {{ background: #1e293b; border-radius: 8px; margin: 16px 0;
                border-left: 4px solid #475569; }}
    .finding-header {{ padding: 12px 16px; display: flex; align-items: center; gap: 12px; }}
    .finding-body {{ padding: 0 16px 16px; color: #cbd5e1; }}
    .finding-body p {{ margin: 6px 0; }}
    code {{ background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
    pre {{ background: #0f172a; padding: 12px; border-radius: 4px; overflow-x: auto;
           font-size: 0.85em; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #334155; }}
    td:first-child {{ color: #94a3b8; width: 140px; }}
    details {{ margin-top: 8px; }}
    summary {{ cursor: pointer; color: #60a5fa; }}
    .section {{ background: #1e293b; border-radius: 8px; padding: 16px; margin: 16px 0; }}
    .title {{ font-weight: 600; color: #f1f5f9; }}
</style>
</head>
<body>
<h1>FHIR Security Scan Report</h1>
<p>Target: <code>{html.escape(result.target)}</code></p>
<p>Scan time: {html.escape(result.start_time)} — {html.escape(result.end_time)}</p>

{ep_section}

<div class="section">
    <h2>Summary</h2>
    <div class="summary">{summary_items}</div>
    <p>Total findings: {len(result.findings)}</p>
</div>

<h2>Findings</h2>
{"".join(findings_html)}

</body>
</html>"""

    output = Path(path)
    output.write_text(report_html)
    console.print(f"[green]HTML report saved to:[/] {output}")
