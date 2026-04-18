"""JSON-in-header fuzzer.

Tests endpoints that accept complex JSON structures embedded in HTTP headers.
Uses DPC's `X-Provenance` header (a full FHIR Provenance resource in a header)
as the primary model but generalizes to any JSON-in-header pattern.

Attack classes covered:
1. Missing required fields — map the validation order
2. Cross-tenant field tampering (claim agency for another organization)
3. JSON parser abuse (malformed JSON, trailing garbage, Unicode oddities)
4. Header injection (CRLF, whitespace handling)
5. Header size limits (oversized payloads)
6. Content-Type confusion (XML in a JSON header field)

Patterns from CMS DPC:
- Missing X-Provenance         → 400 "Must have X-Provenance header"
- Non-JSON content             → 400 "Cannot parse FHIR Provenance resource"
- Valid JSON, wrong shape      → 400 "Cannot parse FHIR Provenance resource"
- Missing agent                → 422 (ProfileValidator error with Java class name leak)
- Cross-practitioner reference → 422 "Could not find provider defined in provenance header"
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
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
class ProvenanceTestResult:
    label: str
    status_code: int
    error_text: str
    response_snippet: str
    triggered_exception: bool = False  # True if 5xx


# A baseline valid Provenance resource (DPC format). Callers can customize.
def default_dpc_provenance(org_id: str, practitioner_id: str) -> dict:
    return {
        "resourceType": "Provenance",
        "meta": {
            "profile": [
                "https://dpc.cms.gov/api/v1/StructureDefinition/dpc-profile-attestation"
            ]
        },
        "recorded": "2026-01-01T00:00:00.000-05:00",
        "reason": [{
            "system": "http://hl7.org/fhir/v3/ActReason",
            "code": "TREAT",
        }],
        "agent": [{
            "role": [{
                "coding": [{
                    "system": "http://hl7.org/fhir/v3/RoleClass",
                    "code": "AGNT",
                }]
            }],
            "whoReference": {"reference": f"Organization/{org_id}"},
            "onBehalfOfReference": {"reference": f"Practitioner/{practitioner_id}"},
        }],
    }


def extract_error(body: str, headers: dict[str, str]) -> str:
    """Extract the error message text from a response body."""
    try:
        d = json.loads(body)
        if isinstance(d, dict):
            issues = d.get("issue", [])
            if issues:
                return (
                    issues[0].get("details", {}).get("text", "")
                    or issues[0].get("diagnostics", "")
                )
            if "error" in d:
                return str(d["error"])
            if "message" in d:
                return str(d["message"])
    except (json.JSONDecodeError, TypeError):
        pass
    return body[:200]


async def _probe(
    client: FHIRClient,
    method: str,
    url: str,
    header_name: str,
    header_value: str,
    body: dict | None = None,
    content_type: str = "application/fhir+json",
) -> ProvenanceTestResult:
    """Send a probe with a specific header value and record the result."""
    headers = {
        "Accept": "application/fhir+json",
        "Content-Type": content_type,
        header_name: header_value,
    }
    try:
        kwargs: dict[str, Any] = {"headers": headers}
        if body is not None:
            kwargs["json_body"] = body
        r = await client.request(method, url, **kwargs)
        return ProvenanceTestResult(
            label="",
            status_code=r.status_code,
            error_text=extract_error(r.text, dict(r.headers)),
            response_snippet=r.text[:300],
            triggered_exception=(r.status_code >= 500),
        )
    except httpx.HTTPError as e:
        return ProvenanceTestResult(
            label="",
            status_code=0,
            error_text=str(e)[:200],
            response_snippet="",
        )


async def run_provenance_fuzz(
    client: FHIRClient,
    result: ScanResult,
    target_url: str,
    method: str = "POST",
    header_name: str = "X-Provenance",
    valid_body: dict | None = None,
    valid_org_id: str = "",
    valid_practitioner_id: str = "",
    other_org_id: str = "00000000-0000-0000-0000-000000000000",
    other_practitioner_id: str = "00000000-0000-0000-0000-000000000000",
) -> list[ProvenanceTestResult]:
    """Run the JSON-in-header fuzz suite.

    Provide `valid_org_id` and `valid_practitioner_id` to get meaningful cross-
    tenant tests. Without these, only the structural tests run.
    """
    console.print(f"\n[bold]JSON-in-header fuzz: {header_name} on {target_url}[/]")

    results: list[ProvenanceTestResult] = []

    # Build a valid baseline Provenance
    if valid_org_id and valid_practitioner_id:
        baseline = default_dpc_provenance(valid_org_id, valid_practitioner_id)
    else:
        baseline = default_dpc_provenance(
            "<org>", "<prac>"
        )

    # ============================================================
    # Structural probes
    # ============================================================
    struct_tests: list[tuple[str, str | None]] = [
        ("missing header", None),
        ("empty string", ""),
        ("whitespace only", "   "),
        ("not JSON", "this is not json at all"),
        ("broken JSON: trailing comma", '{"resourceType":"Provenance",}'),
        ("broken JSON: unterminated", '{"resourceType":"Provenance"'),
        ("broken JSON: unterminated string", '{"resourceType":"Provenance","recorded":"2026-01-01'),
        ("JSON array instead of object", '[{"resourceType":"Provenance"}]'),
        ("JSON primitive", '"just a string"'),
        ("JSON null", 'null'),
        ("JSON number", '42'),
        ("JSON: wrong resourceType", '{"resourceType":"Patient"}'),
        ("JSON: empty object", '{}'),
        ("XML content", '<Provenance><recorded>x</recorded></Provenance>'),
        ("binary garbage", '\x00\x01\x02\x03'),
        # Large payload
        ("oversized (10KB)", '{"resourceType":"Provenance","padding":"' + "A" * 10000 + '"}'),
        ("oversized (100KB)", '{"resourceType":"Provenance","padding":"' + "A" * 100000 + '"}'),
        # Header injection attempts
        ("CRLF injection", '{"resourceType":"Provenance"}\r\nX-Injected: value'),
        ("null byte", '{"resourceType":"Provenance"}\x00'),
        # Unicode abuse
        ("unicode control chars", '{"resourceType":"\u0000Provenance"}'),
        ("byte order mark", '\ufeff{"resourceType":"Provenance"}'),
        # Content-type confusion (send XML but claim JSON)
        ("XML tag sprinkled in JSON", '{"resourceType":"Provenance","extra":"<script>"}'),
    ]

    for label, value in struct_tests:
        if value is None:
            # Skip the header entirely
            headers = {"Accept": "application/fhir+json", "Content-Type": "application/fhir+json"}
            try:
                r = await client.request(
                    method, target_url, headers=headers,
                    json_body=valid_body or {},
                )
                res = ProvenanceTestResult(
                    label=label,
                    status_code=r.status_code,
                    error_text=extract_error(r.text, dict(r.headers)),
                    response_snippet=r.text[:300],
                    triggered_exception=(r.status_code >= 500),
                )
            except httpx.HTTPError as e:
                res = ProvenanceTestResult(
                    label=label, status_code=0,
                    error_text=str(e)[:200], response_snippet="",
                )
        else:
            res = await _probe(
                client, method, target_url, header_name, value,
                body=valid_body or {},
            )
        res.label = label
        results.append(res)

        marker = "⚠" if res.triggered_exception else " "
        console.print(f"  {marker} [{res.status_code}] {label}: {res.error_text[:100]}")

    # ============================================================
    # Cross-tenant field tampering (only if we have a baseline)
    # ============================================================
    if valid_org_id and valid_practitioner_id:
        console.print("\n  [cyan]Cross-tenant tampering tests:[/]")

        # Cross-org agent
        crossed = json.loads(json.dumps(baseline))  # deep copy
        crossed["agent"][0]["whoReference"]["reference"] = f"Organization/{other_org_id}"
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "cross-org agent whoReference"
        results.append(res)
        console.print(f"    [{res.status_code}] cross-org agent: {res.error_text[:100]}")

        # Cross-practitioner
        crossed = json.loads(json.dumps(baseline))
        crossed["agent"][0]["onBehalfOfReference"]["reference"] = (
            f"Practitioner/{other_practitioner_id}"
        )
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "cross-practitioner onBehalfOfReference"
        results.append(res)
        console.print(f"    [{res.status_code}] cross-practitioner: {res.error_text[:100]}")

        # Practitioner from no one
        crossed = json.loads(json.dumps(baseline))
        crossed["agent"][0]["onBehalfOfReference"]["reference"] = "Practitioner/null"
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "null practitioner reference"
        results.append(res)
        console.print(f"    [{res.status_code}] null practitioner: {res.error_text[:100]}")

        # Missing agent entirely
        crossed = json.loads(json.dumps(baseline))
        del crossed["agent"]
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "no agent field"
        results.append(res)
        console.print(f"    [{res.status_code}] no agent: {res.error_text[:100]}")

        # Missing recorded
        crossed = json.loads(json.dumps(baseline))
        del crossed["recorded"]
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "no recorded timestamp"
        results.append(res)
        console.print(f"    [{res.status_code}] no recorded: {res.error_text[:100]}")

        # Wrong reason code
        crossed = json.loads(json.dumps(baseline))
        crossed["reason"] = [{"system": "http://hl7.org/fhir/v3/ActReason", "code": "FAKE"}]
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "invalid reason code"
        results.append(res)
        console.print(f"    [{res.status_code}] invalid reason: {res.error_text[:100]}")

        # Duplicate agents (multiple organizations)
        crossed = json.loads(json.dumps(baseline))
        extra_agent = json.loads(json.dumps(baseline["agent"][0]))
        extra_agent["whoReference"]["reference"] = f"Organization/{other_org_id}"
        crossed["agent"].append(extra_agent)
        res = await _probe(
            client, method, target_url, header_name,
            json.dumps(crossed), body=valid_body or {},
        )
        res.label = "duplicate agent with cross-org ref"
        results.append(res)
        console.print(f"    [{res.status_code}] multi-org agent: {res.error_text[:100]}")

    # ============================================================
    # Analyze and report findings
    # ============================================================
    _analyze_provenance_results(target_url, header_name, results, result)
    return results


def _analyze_provenance_results(
    target_url: str,
    header_name: str,
    results: list[ProvenanceTestResult],
    result: ScanResult,
) -> None:
    """Summarize and report findings."""
    # Count 5xx errors
    unhandled = [r for r in results if r.triggered_exception]
    if unhandled:
        unique_errs = set(r.error_text[:150] for r in unhandled)
        result.add_finding(Finding(
            title=f"JSON-in-header ({header_name}) triggered {len(unique_errs)} unhandled exception(s)",
            severity=Severity.MEDIUM,
            category=FindingCategory.CONFIG,
            description=(
                f"Malformed {header_name} header values trigger HTTP 5xx responses "
                f"indicating missing exception handling in the header parsing code path."
            ),
            endpoint=target_url,
            evidence={
                "header": header_name,
                "triggering_probes": [r.label for r in unhandled],
                "unique_errors": sorted(unique_errs),
            },
        ))

    # Count distinct error messages
    distinct_errors = set(
        r.error_text[:150] for r in results
        if r.status_code >= 400 and r.error_text
    )
    if len(distinct_errors) >= 5:
        result.add_finding(Finding(
            title=f"{header_name} validation order leaked via {len(distinct_errors)} distinct error messages",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                f"The {header_name} header validator returns unique error messages "
                f"for each validation step, enabling attackers to map the validation "
                f"chain and craft bypass probes."
            ),
            endpoint=target_url,
            evidence={"distinct_errors": sorted(distinct_errors)[:20]},
        ))

    # Check for cross-tenant accept (critical)
    cross_tenant = [
        r for r in results
        if "cross-" in r.label and r.status_code in (200, 201)
    ]
    if cross_tenant:
        result.add_finding(Finding(
            title=f"Cross-tenant reference accepted in {header_name} header",
            severity=Severity.CRITICAL,
            category=FindingCategory.AUTHZ,
            description=(
                f"The {header_name} validator accepted cross-tenant references "
                f"(agent references pointing to other organizations/practitioners). "
                f"This could allow unauthorized attestation / write operations on "
                f"behalf of other tenants."
            ),
            endpoint=target_url,
            evidence={
                "successful_cross_tenant_probes": [r.label for r in cross_tenant],
            },
        ))
