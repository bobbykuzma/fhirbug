"""Response serialization bug detection.

Tests for:
1. HAPI FHIR internal field leaks (formatCommentsPre, formatCommentsPost, etc.)
2. Empty-body response amplification (DoS surface)
3. Stack trace / internal error leakage in error responses
4. Debug headers / internal IDs exposed

Pattern discovered on CMS DPC: empty POST body to /Token/validate returned
168 KB response with internal HAPI FHIR object fields that should never be
serialized to clients (formatCommentsPre/Post marked @JsonIgnore in HAPI).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
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

# Internal HAPI FHIR fields that should never be serialized to clients
HAPI_INTERNAL_FIELDS = {
    "formatCommentsPre",
    "formatCommentsPost",
    "userData",
    "valueAsString",  # not always internal, but worth flagging
}

# Stack trace / debug indicators
STACK_TRACE_INDICATORS = [
    "Traceback (most recent call",
    "at java.",
    "at org.springframework.",
    "at com.sun.",
    "at jakarta.",
    "at gov.cms.",
    "NullPointerException",
    "ClassCastException",
    "IllegalArgumentException",
    "java.lang.",
    "StackTraceElement",
    "File \"/",
    "line ",  # generic but often appears in Python tracebacks
]

# Sensitive header names that shouldn't be exposed
SENSITIVE_DEBUG_HEADERS = [
    "x-debug", "x-stack-trace", "x-error", "x-exception",
    "x-internal-id", "x-request-id",  # the last 2 are informational but flag
    "server",  # version disclosure
    "x-powered-by",
    "x-aspnet-version", "x-aspnetmvc-version",
]


@dataclass
class SerializationProbeResult:
    endpoint: str
    request_method: str
    request_body_size: int
    response_status: int
    response_size: int
    response_body: str
    response_headers: dict[str, str]
    amplification_ratio: float
    internal_fields_found: list[str]
    stack_trace_hints: list[str]


def find_internal_fields(obj: Any, found: set[str] | None = None) -> set[str]:
    """Recursively look for HAPI internal fields in a JSON object."""
    if found is None:
        found = set()
    if isinstance(obj, dict):
        for k in obj.keys():
            if k in HAPI_INTERNAL_FIELDS:
                found.add(k)
        for v in obj.values():
            find_internal_fields(v, found)
    elif isinstance(obj, list):
        for item in obj:
            find_internal_fields(item, found)
    return found


def find_stack_trace_hints(text: str) -> list[str]:
    """Look for stack trace / debug indicators in response text."""
    hints = []
    for indicator in STACK_TRACE_INDICATORS:
        if indicator in text:
            hints.append(indicator)
    return hints


async def probe_endpoint_for_serialization_bugs(
    client: FHIRClient,
    url: str,
    method: str = "POST",
    body: bytes = b"",
    content_type: str = "text/plain",
) -> SerializationProbeResult | None:
    """Send a probe request and analyze the response for serialization issues."""
    try:
        r = await client.request(
            method,
            url,
            headers={
                "Content-Type": content_type,
                "Accept": "application/json",
            },
            raw_body=body.decode() if body else "",
        )
    except httpx.HTTPError:
        return None

    response_body = r.text
    response_size = len(response_body)
    request_size = len(body)

    amplification = response_size / max(request_size, 1)

    # Look for internal fields
    internal_found = []
    try:
        parsed = json.loads(response_body)
        internal_found = sorted(find_internal_fields(parsed))
    except (json.JSONDecodeError, ValueError):
        # Not JSON — just check for field names as strings
        for field in HAPI_INTERNAL_FIELDS:
            if field in response_body:
                internal_found.append(field)

    stack_hints = find_stack_trace_hints(response_body)

    return SerializationProbeResult(
        endpoint=url,
        request_method=method,
        request_body_size=request_size,
        response_status=r.status_code,
        response_size=response_size,
        response_body=response_body[:500],
        response_headers=dict(r.headers),
        amplification_ratio=amplification,
        internal_fields_found=internal_found,
        stack_trace_hints=stack_hints,
    )


async def run_serialization_scan(
    client: FHIRClient,
    result: ScanResult,
    endpoints: list[str],
) -> None:
    """Run the serialization bug scan against a list of endpoints."""
    console.print("\n[bold]Running serialization bug tests...[/]")

    all_results: list[SerializationProbeResult] = []

    probe_bodies = [
        ("empty body", b"", "text/plain"),
        ("empty body + json ct", b"", "application/json"),
        ("empty body + fhir ct", b"", "application/fhir+json"),
        ("one byte", b"x", "text/plain"),
        ("empty json", b"{}", "application/json"),
        ("empty array", b"[]", "application/json"),
        ("null json", b"null", "application/json"),
        ("malformed json", b"{", "application/json"),
    ]

    for url in endpoints:
        console.print(f"\n  [cyan]Probing:[/] {url}")

        endpoint_results: list[SerializationProbeResult] = []
        for label, body, ct in probe_bodies:
            res = await probe_endpoint_for_serialization_bugs(
                client, url, method="POST", body=body, content_type=ct
            )
            if not res:
                continue

            endpoint_results.append(res)

            markers = []
            if res.internal_fields_found:
                markers.append(f"INTERNAL:{','.join(res.internal_fields_found)}")
            if res.stack_trace_hints:
                markers.append(f"TRACE:{len(res.stack_trace_hints)}")
            if res.amplification_ratio > 100 and res.request_body_size <= 1:
                markers.append(f"AMP:{res.amplification_ratio:.0f}x")

            marker_str = " ".join(markers) if markers else "ok"
            console.print(
                f"    [{res.response_status}] {label}: "
                f"{res.response_size} bytes  [{marker_str}]"
            )

        # Suppress findings from constant intermediary error pages.
        # If every probe (different bodies, different content-types) returns
        # the SAME response body, the response is not generated from our
        # request — it's a static page from a WAF / reverse proxy / load
        # balancer that intercepted the request before the FHIR layer.
        # Same goes for HTML responses (a real FHIR server returns JSON/XML).
        if endpoint_results:
            unique_bodies = {r.response_body for r in endpoint_results}
            first_ct = (
                endpoint_results[0].response_headers.get("content-type", "").lower()
                if endpoint_results else ""
            )
            looks_like_html = (
                "html" in first_ct
                or any(
                    r.response_body.lstrip().lower().startswith(("<!doctype", "<html"))
                    for r in endpoint_results
                )
            )
            if len(unique_bodies) <= 1 or looks_like_html:
                console.print(
                    "    [yellow]skipping endpoint:[/] responses are constant "
                    "or HTML — likely a WAF/proxy intermediary, not the FHIR server"
                )
                continue

        all_results.extend(endpoint_results)

    # Generate findings
    # Finding 1: HAPI FHIR internal field leak
    leaks = [r for r in all_results if r.internal_fields_found]
    if leaks:
        unique_fields = set()
        for r in leaks:
            unique_fields.update(r.internal_fields_found)
        unique_endpoints = set(r.endpoint for r in leaks)

        result.add_finding(Finding(
            title="HAPI FHIR internal object fields leaked in response bodies",
            severity=Severity.HIGH,
            category=FindingCategory.INFO_DISC,
            description=(
                "The server returns responses containing HAPI FHIR internal fields "
                "that should never be serialized to clients. These fields are marked "
                "@JsonIgnore in HAPI FHIR's default configuration. Their presence indicates "
                "a custom/broken JSON serializer that bypasses HAPI's annotations, exposing "
                "the internal object model to clients."
                f"\n\nLeaked fields: {sorted(unique_fields)}"
                f"\nAffected endpoints: {sorted(unique_endpoints)}"
            ),
            endpoint=next(iter(unique_endpoints)),
            evidence={
                "leaked_fields": sorted(unique_fields),
                "affected_endpoints": sorted(unique_endpoints),
                "sample_triggers": [
                    {"endpoint": r.endpoint, "request_body_size": r.request_body_size,
                     "response_size": r.response_size,
                     "response_snippet": r.response_body[:300]}
                    for r in leaks[:3]
                ],
            },
            remediation=(
                "Configure the HAPI FHIR JSON serializer to honor @JsonIgnore annotations. "
                "Alternatively, use HAPI's default FhirContext.newJsonParser() for all "
                "error response serialization. Audit the custom OperationOutcome builder "
                "for misuse of object mappers that bypass Jackson's ignore annotations."
            ),
        ))

    # Finding 2: DoS amplification
    amplification_cases = [
        r for r in all_results
        if r.amplification_ratio > 1000 and r.request_body_size <= 10
    ]
    if amplification_cases:
        max_amp = max(r.amplification_ratio for r in amplification_cases)
        max_case = max(amplification_cases, key=lambda r: r.response_size)

        result.add_finding(Finding(
            title=f"Response size amplification (up to {max_amp:.0f}x) from tiny requests",
            severity=Severity.MEDIUM,
            category=FindingCategory.CONFIG,
            description=(
                f"The server returns disproportionately large responses (up to "
                f"{max_case.response_size:,} bytes) for tiny requests "
                f"({max_case.request_body_size} bytes). This provides a bandwidth "
                f"amplification vector for DoS attacks — an attacker can send minimal "
                f"requests and generate large egress traffic."
            ),
            endpoint=max_case.endpoint,
            evidence={
                "max_amplification_ratio": max_amp,
                "max_response_size": max_case.response_size,
                "amplification_cases": [
                    {"endpoint": r.endpoint, "req_size": r.request_body_size,
                     "resp_size": r.response_size, "ratio": r.amplification_ratio}
                    for r in amplification_cases
                ],
            },
            remediation=(
                "Reject empty or near-empty request bodies with a small error response. "
                "Configure error response generation to not serialize large object graphs "
                "when the request was not understood."
            ),
        ))

    # Finding 3: Stack trace leakage
    traces = [r for r in all_results if r.stack_trace_hints]
    if traces:
        unique_indicators = set()
        for r in traces:
            unique_indicators.update(r.stack_trace_hints)

        result.add_finding(Finding(
            title="Error responses contain stack trace / framework debug indicators",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                "Error responses leak internal exception information useful for attacker "
                "reconnaissance. Indicators found: " + ", ".join(sorted(unique_indicators))
            ),
            endpoint=traces[0].endpoint,
            evidence={
                "indicators": sorted(unique_indicators),
                "sample_responses": [r.response_body[:300] for r in traces[:3]],
            },
            remediation=(
                "Implement a global exception handler that sanitizes error messages "
                "before returning them to clients. Log stack traces server-side only."
            ),
        ))
