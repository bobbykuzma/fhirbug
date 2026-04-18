"""FHIR-specific injection testing — resource creation, header injection, content-type abuse."""

from __future__ import annotations

import json
from typing import Any

import httpx
from rich.console import Console

from fhirbug.core.client import FHIRClient
from fhirbug.core.config import TargetConfig
from fhirbug.core.models import (
    EndpointInfo,
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


async def test_content_type_handling(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test how the server handles unexpected content types and formats."""
    console.print("\n[bold]Testing content-type handling...[/]")

    url = config.resource_url("Patient") if "Patient" in info.supported_resources else config.resource_url(info.supported_resources[0])

    # Test XML content-type on a JSON endpoint
    test_cases = [
        ("application/xml", "<Patient xmlns='http://hl7.org/fhir'><name><text>test</text></name></Patient>"),
        ("text/plain", "this is not FHIR"),
        ("application/x-www-form-urlencoded", "resourceType=Patient&name=test"),
        ("multipart/form-data", "------boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ntest\r\n------boundary--"),
    ]

    for content_type, body in test_cases:
        try:
            resp = await client.request(
                "POST", url,
                headers={
                    "Content-Type": content_type,
                    "Accept": "application/fhir+json",
                },
                raw_body=body,
            )

            if resp.status_code == 200 or resp.status_code == 201:
                result.add_finding(Finding(
                    title=f"Server accepted unexpected content-type: {content_type}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.INJECTION,
                    description=(
                        f"A POST with Content-Type: {content_type} was accepted "
                        f"(status {resp.status_code}). This may indicate loose "
                        "input parsing that could be exploited."
                    ),
                    endpoint=url,
                    evidence={
                        "content_type": content_type,
                        "status": resp.status_code,
                        "response_snippet": resp.text[:300],
                    },
                ))

            # Check for stack traces in error responses
            if resp.status_code >= 400:
                body_text = resp.text.lower()
                if any(ind in body_text for ind in ["stack", "trace", "exception", "at com.", "at org."]):
                    result.add_finding(Finding(
                        title=f"Stack trace leaked on malformed {content_type} request",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.INFO_DISC,
                        description=(
                            "Server returned internal error details (stack trace) "
                            "when processing a malformed request."
                        ),
                        endpoint=url,
                        evidence={
                            "content_type": content_type,
                            "status": resp.status_code,
                            "response_snippet": resp.text[:500],
                        },
                    ))

        except httpx.HTTPError:
            pass


async def test_header_injection(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test for header-based attacks on the FHIR endpoint."""
    console.print("\n[bold]Testing header-based attacks...[/]")

    url = config.resource_url("Patient") if "Patient" in info.supported_resources else config.metadata_url()

    # X-Forwarded-For / Host header manipulation
    header_tests: list[tuple[str, dict[str, str], str]] = [
        (
            "X-Forwarded-For bypass",
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
            "internal_access",
        ),
        (
            "Host header injection",
            {"Host": "evil.example.com"},
            "host_injection",
        ),
        (
            "X-HTTP-Method-Override",
            {"X-HTTP-Method-Override": "DELETE"},
            "method_override",
        ),
        (
            "X-Original-URL override",
            {"X-Original-URL": "/admin"},
            "url_override",
        ),
        (
            "FHIR _format header override",
            {"_format": "application/xml"},
            "format_override",
        ),
    ]

    for test_name, headers, test_type in header_tests:
        try:
            resp = await client.get(url, headers=headers)

            if test_type == "method_override" and resp.status_code in (200, 204, 410):
                # If method override to DELETE succeeded, that's bad
                result.add_finding(Finding(
                    title="X-HTTP-Method-Override accepted",
                    severity=Severity.HIGH,
                    category=FindingCategory.AUTHZ,
                    description=(
                        "The server honors X-HTTP-Method-Override header, allowing "
                        "GET requests to be treated as DELETE/PUT/PATCH. This can "
                        "bypass method-based access controls."
                    ),
                    endpoint=url,
                    evidence={
                        "header": "X-HTTP-Method-Override: DELETE",
                        "status": resp.status_code,
                    },
                ))
                console.print(f"  [red]X-HTTP-Method-Override accepted![/]")

        except httpx.HTTPError:
            pass


async def test_operation_injection(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test FHIR operations for injection and misconfiguration."""
    console.print("\n[bold]Testing FHIR operations...[/]")

    base = config.base_url.rstrip("/")

    # Test $validate — does it leak schema info?
    if "Patient" in info.supported_resources:
        validate_url = f"{base}/Patient/$validate"
        try:
            malformed = {
                "resourceType": "Patient",
                "name": [{"use": "official", "text": "test"}],
                "INVALID_FIELD": "test",
                "birthDate": "not-a-date",
            }
            resp = await client.post(
                validate_url,
                json_body={"resourceType": "Parameters", "parameter": [
                    {"name": "resource", "resource": malformed}
                ]},
            )
            if resp.status_code == 200:
                body = resp.json()
                issues = body.get("issue", [])
                if issues:
                    console.print(f"  [yellow]$validate returned {len(issues)} validation issues — schema info exposed[/]")
                    result.add_finding(Finding(
                        title="$validate exposes detailed schema validation",
                        severity=Severity.LOW,
                        category=FindingCategory.INFO_DISC,
                        description=(
                            "$validate returns detailed field-level validation errors, "
                            "which aids an attacker in understanding the exact data "
                            "model and crafting valid-looking forged resources."
                        ),
                        endpoint=validate_url,
                        evidence={"issue_count": len(issues), "sample_issues": issues[:3]},
                    ))

        except httpx.HTTPError:
            pass

    # Test $everything on Patient — mass exfil
    if "Patient" in info.supported_resources:
        # Get a patient ID first
        try:
            resp = await client.get(
                config.resource_url("Patient"),
                params={"_count": "1"},
            )
            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("entry", [])
                if entries:
                    pid = entries[0].get("resource", {}).get("id", "")
                    if pid:
                        everything_url = f"{base}/Patient/{pid}/$everything"
                        resp = await client.get(everything_url)
                        if resp.status_code == 200:
                            body = resp.json()
                            entries = body.get("entry", [])
                            types = {
                                e.get("resource", {}).get("resourceType", "")
                                for e in entries
                            }
                            types.discard("")
                            result.add_finding(Finding(
                                title=f"Patient/$everything returned {len(entries)} resources across {len(types)} types",
                                severity=Severity.HIGH,
                                category=FindingCategory.DATA_LEAK,
                                description=(
                                    f"Patient/{pid}/$everything returned the complete "
                                    f"patient record: {len(entries)} entries spanning "
                                    f"types {sorted(types)}. Verify this is scoped to "
                                    "the authorized patient only."
                                ),
                                endpoint=everything_url,
                                evidence={
                                    "patient_id": pid,
                                    "entry_count": len(entries),
                                    "types": sorted(types),
                                },
                            ))
                            console.print(
                                f"  [yellow]$everything on Patient/{pid}: "
                                f"{len(entries)} entries, types={sorted(types)}[/]"
                            )
        except httpx.HTTPError:
            pass

    # Test $export — bulk data
    export_url = f"{base}/$export"
    try:
        resp = await client.get(
            export_url,
            headers={"Accept": "application/fhir+json", "Prefer": "respond-async"},
        )
        if resp.status_code in (200, 202):
            result.add_finding(Finding(
                title="Bulk $export operation accessible",
                severity=Severity.HIGH,
                category=FindingCategory.DATA_LEAK,
                description=(
                    f"System-level $export returned {resp.status_code}. "
                    "If this operation succeeds, it exports ALL data from the "
                    "server. Verify that backend-services auth is required."
                ),
                endpoint=export_url,
                evidence={
                    "status": resp.status_code,
                    "content_location": resp.headers.get("Content-Location", ""),
                },
            ))
            console.print(f"  [red]$export returned {resp.status_code}![/]")
        else:
            console.print(f"  [green]$export returned {resp.status_code}[/]")
    except httpx.HTTPError:
        pass
