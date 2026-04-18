"""OAuth client ID enumeration detection.

Pattern: when OAuth token/authorize endpoints return distinguishable responses
for "valid client_id, wrong credentials" vs "invalid client_id", an attacker
can enumerate registered OAuth clients. Violates RFC 6749 §5.2.

Found in:
- CMS BB2 /v2/o/token/ (HTTP 401 vs 400 with different error_description)
- CMS AB2D Okta (OAuth-format vs Okta-format error body)
- CMS DPC /Token/auth ("Cannot find public key with id" vs "Invalid JWT")
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from rich.console import Console

from fhirbug.core.client import FHIRClient
from fhirbug.core.config import TargetConfig
from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


@dataclass
class EnumProbeResult:
    label: str
    status_code: int
    body: str
    body_signature: str  # canonicalized "shape" of the body for comparison


def canonicalize_response(body: str) -> str:
    """Normalize a response body so we can compare 'shapes' across probes."""
    try:
        d = json.loads(body)

        def _canon(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: _canon(v) if k != "error_description" else "<VARIABLE>"
                        for k, v in sorted(obj.items())
                        if k not in ("errorId", "id", "trace_id", "request_id", "requestId")}
            if isinstance(obj, list):
                return [_canon(x) for x in obj]
            if isinstance(obj, str):
                return "<STR>"
            return obj

        return json.dumps(_canon(d), sort_keys=True)
    except (json.JSONDecodeError, TypeError):
        # HTML or other — just return length + first tag
        return f"non-json:{len(body)}:{body[:50]}"


async def probe_client_enum_on_token_endpoint(
    client: FHIRClient,
    token_url: str,
    valid_client_id: str,
) -> list[EnumProbeResult]:
    """Probe the token endpoint for client enumeration discrepancy."""
    import base64

    async def _probe(label: str, client_id: str, secret: str = "") -> EnumProbeResult:
        # Use Basic auth with client_id:secret
        auth_str = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        try:
            r = await client.post(
                token_url,
                headers={
                    "Authorization": f"Basic {auth_str}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            return EnumProbeResult(
                label=label,
                status_code=r.status_code,
                body=r.text[:1000],
                body_signature=canonicalize_response(r.text),
            )
        except httpx.HTTPError as e:
            return EnumProbeResult(
                label=label,
                status_code=0,
                body=str(e)[:200],
                body_signature=f"error:{type(e).__name__}",
            )

    results = []

    # Test with valid client_id, wrong/no secret
    results.append(await _probe("valid_client_no_secret", valid_client_id, ""))
    results.append(await _probe("valid_client_wrong_secret", valid_client_id, "wrongpw_xxx"))

    # Test with invalid client_ids (various formats)
    invalid_candidates = [
        ("invalid_random", "totally_fake_client_12345_xyz"),
        ("invalid_uuid", "00000000-0000-0000-0000-000000000000"),
        ("invalid_empty", ""),
        ("invalid_numeric", "123456"),
    ]
    for label, cid in invalid_candidates:
        results.append(await _probe(label, cid, "wrongpw"))

    return results


async def probe_client_enum_via_authorize(
    client: FHIRClient,
    authorize_url: str,
    valid_client_id: str,
    redirect_uri: str = "http://localhost/cb",
) -> list[EnumProbeResult]:
    """Probe the authorize endpoint for client enumeration."""

    async def _probe(label: str, client_id: str) -> EnumProbeResult:
        try:
            r = await client.get(
                authorize_url,
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": "openid",
                    "state": "enum_test",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                },
            )
            return EnumProbeResult(
                label=label,
                status_code=r.status_code,
                body=r.text[:1000],
                body_signature=canonicalize_response(r.text),
            )
        except httpx.HTTPError as e:
            return EnumProbeResult(
                label=label,
                status_code=0,
                body=str(e)[:200],
                body_signature=f"error:{type(e).__name__}",
            )

    results = []
    results.append(await _probe("valid_client", valid_client_id))
    results.append(await _probe("invalid_random", "totally_fake_client_xyz"))
    results.append(await _probe("invalid_uuid", "00000000-0000-0000-0000-000000000000"))
    return results


def analyze_enum_results(
    endpoint: str,
    results: list[EnumProbeResult],
    result: ScanResult,
) -> None:
    """Check if the results show an enumeration discrepancy."""
    # Group results by "valid" vs "invalid" prefix
    valid_results = [r for r in results if r.label.startswith("valid")]
    invalid_results = [r for r in results if r.label.startswith("invalid")]

    if not valid_results or not invalid_results:
        return

    valid_signatures = set(r.body_signature for r in valid_results)
    invalid_signatures = set(r.body_signature for r in invalid_results)

    valid_codes = set(r.status_code for r in valid_results)
    invalid_codes = set(r.status_code for r in invalid_results)

    # Check for discriminator
    has_code_discriminator = valid_codes != invalid_codes
    has_body_discriminator = not (valid_signatures & invalid_signatures)

    if has_code_discriminator or has_body_discriminator:
        console.print(
            f"  [red]🚨 Enumeration discriminator found on {endpoint}[/]"
        )
        console.print(f"    Valid client codes:   {valid_codes}")
        console.print(f"    Invalid client codes: {invalid_codes}")

        result.add_finding(Finding(
            title=f"OAuth client ID enumeration via response discrepancy on {endpoint}",
            severity=Severity.MEDIUM,
            category=FindingCategory.INFO_DISC,
            description=(
                "The endpoint returns measurably different responses for valid vs invalid "
                "client_id values, enabling unauthenticated remote enumeration of registered "
                "OAuth clients. Violates RFC 6749 §5.2."
                f"\n\nValid client status codes: {sorted(valid_codes)}"
                f"\nInvalid client status codes: {sorted(invalid_codes)}"
                f"\nBody discriminator: {has_body_discriminator}"
            ),
            endpoint=endpoint,
            evidence={
                "valid_responses": [
                    {"label": r.label, "status": r.status_code,
                     "body_snippet": r.body[:200]}
                    for r in valid_results
                ],
                "invalid_responses": [
                    {"label": r.label, "status": r.status_code,
                     "body_snippet": r.body[:200]}
                    for r in invalid_results
                ],
            },
            remediation=(
                "Return identical HTTP responses (status code, body, headers) for both "
                "'client exists with wrong credentials' and 'client does not exist'. "
                "A safe pattern is: return 401 {\"error\": \"invalid_client\"} for both "
                "without any error_description that distinguishes the cases."
            ),
        ))
    else:
        console.print(
            f"  [green]✓ No enumeration discriminator on {endpoint}[/]"
        )


async def run_client_enumeration_scan(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    token_url: str | None = None,
    authorize_url: str | None = None,
    valid_client_id: str = "",
) -> None:
    """Run the full client enumeration detection scan."""
    console.print("\n[bold]Running OAuth client ID enumeration tests...[/]")

    if not valid_client_id:
        console.print("  [yellow]No valid client_id provided — skipping[/]")
        return

    if token_url:
        console.print(f"\n  [cyan]Testing token endpoint:[/] {token_url}")
        results = await probe_client_enum_on_token_endpoint(
            client, token_url, valid_client_id
        )
        analyze_enum_results(token_url, results, result)

    if authorize_url:
        console.print(f"\n  [cyan]Testing authorize endpoint:[/] {authorize_url}")
        results = await probe_client_enum_via_authorize(
            client, authorize_url, valid_client_id
        )
        analyze_enum_results(authorize_url, results, result)
