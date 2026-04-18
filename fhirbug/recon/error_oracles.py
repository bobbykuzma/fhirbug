"""Error message oracle mapping.

Sends a series of crafted probes to an endpoint and catalogs the distinct
error messages returned. Used to:

1. Map the server's validation order (each distinct error = one validation step)
2. Detect enumeration oracles (different messages for "not found" vs "unauthorized"
   vs "signature invalid")
3. Fingerprint custom error messages that hint at framework / language / internals

Pattern from CMS DPC:
- "Invalid JWT"
- "JWT is not formatted correctly"
- "JWT header must have `kid` value"
- "JWT must have client_id"
- "Issuer and Subject must be identical"
- "JWT client token must have organization_id"
- "Cannot find public key with id: X"
- "Cannot deserialize Macaroon"
- "UUID string too large"
- "Cannot invoke \"String.length()\" because \"name\" is null"

Each unique error maps a validation step. Eight distinct errors = rich
attack surface visibility.
"""

from __future__ import annotations

import base64
import json
import re
import time
import uuid as uuid_mod
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from rich.console import Console
from rich.table import Table

from fhirbug.core.client import FHIRClient
from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


@dataclass
class OracleProbe:
    """A single probe that attempts to trigger a specific validation step."""
    label: str             # human description of what this probe is testing
    status_code: int = 0
    error_text: str = ""
    body_prefix: str = ""  # first ~200 chars of response
    response_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class OracleReport:
    endpoint: str
    probes: list[OracleProbe] = field(default_factory=list)
    # A map from "canonical error text" to the list of probes that trigger it.
    error_to_probes: dict[str, list[str]] = field(default_factory=dict)
    distinct_errors: int = 0
    has_stack_trace_leak: bool = False
    has_enum_oracle: bool = False
    enum_pairs: list[tuple[str, str]] = field(default_factory=list)  # (existed, not_existed) label pairs
    framework_hints: list[str] = field(default_factory=list)


# Error text indicators that suggest a specific framework/language
FRAMEWORK_ERROR_HINTS = {
    "Java": ["Cannot invoke", "NullPointerException", "ClassCastException",
             "IllegalArgumentException", "at java.", "at org.", "at com.",
             "at jakarta.", "Cannot deserialize", "UUID string"],
    "Spring": ["Spring", "@RequestMapping", "HttpMessageNotReadable",
               "MethodArgumentNotValidException", "HandlerMethod"],
    "HAPI FHIR": ["OperationOutcome", "FhirInstanceValidator", "ca.uhn.fhir",
                   "HAPI-0", "resourceType\":\"OperationOutcome"],
    "Django": ["DoesNotExist", "IntegrityError", "ValidationError",
                "django.", "request.POST", "CSRF"],
    "Django REST": ["permission to perform", "detail\"", "not_found",
                     "authentication_failed"],
    "Node.js / Express": ["SyntaxError", "at new Promise", "at process."],
    "Python": ["Traceback (most recent call last)", "File \"/", "line "],
    "Rails": ["ActionController", "ActiveRecord::"],
    "ASP.NET": ["System.Exception", "Microsoft.AspNetCore", "IdentityServer"],
    "Dropwizard": ["io.dropwizard", "com.codahale.metrics"],
}


def extract_error_text(body: str, headers: dict[str, str]) -> str:
    """Extract a concise error message from a response body.

    Tries in order:
    1. Parse as JSON and pull out FHIR OperationOutcome / OAuth / DRF / Okta fields
    2. If JSON parsing fails (e.g. HAPI FHIR malformed response), regex-scan for
       known error text patterns
    3. HTML title extraction
    4. Raw body prefix
    """
    ct = headers.get("content-type", "").lower()

    def _extract_from_dict(d: dict) -> str:
        if not isinstance(d, dict):
            return ""
        # FHIR OperationOutcome
        issues = d.get("issue", [])
        if issues:
            return (
                issues[0].get("details", {}).get("text", "")
                or issues[0].get("diagnostics", "")
                or issues[0].get("code", "")
            )
        # OAuth error format
        if "error_description" in d:
            return f"{d.get('error', '')}: {d['error_description']}"
        if "error" in d:
            err = d["error"]
            if isinstance(err, dict):
                return err.get("message", str(err))
            return str(err)
        # Detail (DRF) / message
        if "detail" in d:
            return str(d["detail"])
        if "message" in d:
            return str(d["message"])
        # Okta-style
        if "errorCode" in d:
            return f"{d['errorCode']}: {d.get('errorSummary', '')}"
        return ""

    # JSON response
    if "json" in ct:
        try:
            d = json.loads(body)
            msg = _extract_from_dict(d)
            if msg:
                return msg
        except (json.JSONDecodeError, TypeError):
            # The body claimed to be JSON but failed to parse.
            # This happens e.g. when HAPI FHIR emits a truncated OperationOutcome.
            # Fall through to regex-based extraction.
            pass

        # Regex fallback for malformed JSON — look for the FHIR issue.details.text
        # pattern directly in the body text
        match = re.search(
            r'"issue"\s*:\s*\[\s*\{[^}]*?"details"\s*:\s*\{[^}]*?"text"\s*:\s*"([^"]+)"',
            body, re.DOTALL,
        )
        if match:
            return match.group(1)
        # Simpler fallback — any "text":"..." inside an issue block
        match = re.search(r'"issue"[\s\S]*?"text"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)
        # OAuth-style
        match = re.search(r'"error_description"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)
        match = re.search(r'"error"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)
        match = re.search(r'"diagnostics"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)

    # HTML response — try to find a title or h1
    if "html" in ct:
        match = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    # Detect HAPI FHIR broken serialization — these responses contain no
    # useful error text but signal the amplification bug
    if "formatCommentsPre" in body[:500] and "formatCommentsPost" in body[:500]:
        return f"[HAPI_SERIALIZATION_LEAK: {len(body)} bytes, no error text]"

    # Plain text / other — strip control chars and limit length
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", body[:200]).strip()
    return re.sub(r"\s+", " ", cleaned)


def canonicalize_error(text: str) -> str:
    """Normalize an error message so we can compare similar errors.

    e.g. "Cannot find public key with id: abc-123" should canonicalize to
    "Cannot find public key with id: <X>" so that probes with different IDs
    all map to the same canonical error.
    """
    # Replace UUIDs
    text = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "<UUID>", text, flags=re.I,
    )
    # Replace long hex strings
    text = re.sub(r"\b[0-9a-f]{20,}\b", "<HEX>", text, flags=re.I)
    # Replace quoted strings (capture the specific value)
    text = re.sub(r"'[^']{3,}'", "'<STR>'", text)
    text = re.sub(r"\"[^\"]{3,}\"", "\"<STR>\"", text)
    # Replace standalone long numbers
    text = re.sub(r"\b\d{6,}\b", "<NUM>", text)
    return text.strip()


def detect_framework(all_errors: list[str]) -> list[str]:
    """Scan error messages for framework fingerprints."""
    found = []
    joined = " ".join(all_errors)
    for fw, patterns in FRAMEWORK_ERROR_HINTS.items():
        if any(p in joined for p in patterns):
            found.append(fw)
    return found


def detect_stack_trace_leak(errors: list[str]) -> bool:
    """Check if any error looks like a leaked stack trace."""
    trace_indicators = [
        "Traceback (most recent call",
        "at java.",
        "at org.springframework.",
        "at org.eclipse.",
        "at com.sun.",
        "at jakarta.",
        "at gov.cms.",
        "at uk.org.",
        "Cannot invoke",
        "NullPointerException",
        "System.Exception",
        "StackTraceElement",
        "File \"/",
    ]
    return any(ind in err for err in errors for ind in trace_indicators)


# ============================================================
# Built-in probe generators for common auth endpoints
# ============================================================

def jwt_probe_generator(
    valid_kid: str = "",
    valid_client_id: str = "",
    target_audience: str = "",
) -> list[tuple[str, dict[str, Any]]]:
    """Generate a library of JWT probes that should each trigger a distinct
    validation step. Returns (label, form_data) tuples where form_data is
    the body to POST to a token endpoint.

    Each JWT payload includes the standard RFC 7523 claims (iss, sub, aud,
    exp, iat, jti) so that probes reach deep validation logic rather than
    bailing out in early header parsing.
    """
    now = int(time.time())

    def b64url(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    def make_jwt(header: dict, payload: dict, sig: bytes = b"fakesig") -> str:
        h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h_b64}.{p_b64}.{b64url(sig)}"

    # Baseline "valid-shape" payload — every probe below derives from this
    # by removing/replacing one field at a time.
    def base_payload(**overrides) -> dict:
        p = {
            "iss": valid_client_id or "fake-issuer",
            "sub": valid_client_id or "fake-issuer",
            "aud": target_audience or "https://unknown/",
            "exp": now + 300,
            "iat": now,
            "jti": str(uuid_mod.uuid4()),
        }
        p.update(overrides)
        return p

    def base_header(**overrides) -> dict:
        h = {"alg": "RS384", "kid": valid_kid or "00000000-0000-0000-0000-000000000000"}
        h.update(overrides)
        return h

    def form(jwt: str, grant: str = "client_credentials", at_type: str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") -> dict:
        return {
            "grant_type": grant,
            "scope": "system/*.*",
            "client_assertion_type": at_type,
            "client_assertion": jwt,
        }

    probes = []

    # ========== Assertion structure probes ==========
    probes.append(("empty client_assertion", form("")))
    probes.append(("not a jwt (plain text)", form("xxxxxxx")))
    probes.append(("jwt one dot", form("header.payload")))
    probes.append(("jwt four dots", form("a.b.c.d.e")))
    probes.append((
        "jwt 2 segments (no sig)",
        form("eyJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJ0ZXN0In0"),
    ))

    # ========== Header probes ==========
    probes.append((
        "jwt empty header {}",
        form(make_jwt({}, base_payload())),
    ))
    probes.append((
        "jwt header no alg",
        form(make_jwt({"kid": "test"}, base_payload())),
    ))
    probes.append((
        "jwt header no kid",
        form(make_jwt({"alg": "RS384"}, base_payload())),
    ))
    probes.append((
        "jwt header alg=none",
        form(make_jwt({"alg": "none", "kid": valid_kid or "test"}, base_payload())),
    ))

    # ========== kid lookup probes ==========
    probes.append((
        "jwt kid=all zeros (not in db)",
        form(make_jwt(
            base_header(kid="00000000-0000-0000-0000-000000000000"),
            base_payload(),
        )),
    ))
    probes.append((
        "jwt kid=not a uuid",
        form(make_jwt(base_header(kid="not-a-uuid-format"), base_payload())),
    ))
    probes.append((
        "jwt kid=empty string",
        form(make_jwt(base_header(kid=""), base_payload())),
    ))

    if valid_kid:
        # ========== Payload probes (these need a real kid to reach deep validation) ==========
        probes.append((
            "jwt no iss",
            form(make_jwt(
                base_header(),
                {k: v for k, v in base_payload().items() if k != "iss"},
            )),
        ))
        probes.append((
            "jwt no sub",
            form(make_jwt(
                base_header(),
                {k: v for k, v in base_payload().items() if k != "sub"},
            )),
        ))
        probes.append((
            "jwt iss != sub",
            form(make_jwt(
                base_header(),
                base_payload(iss=(valid_client_id or "a"), sub="different"),
            )),
        ))
        probes.append((
            "jwt no aud",
            form(make_jwt(
                base_header(),
                {k: v for k, v in base_payload().items() if k != "aud"},
            )),
        ))
        probes.append((
            "jwt wrong aud",
            form(make_jwt(
                base_header(),
                base_payload(aud="https://evil.example.com/"),
            )),
        ))
        probes.append((
            "jwt no exp",
            form(make_jwt(
                base_header(),
                {k: v for k, v in base_payload().items() if k != "exp"},
            )),
        ))
        probes.append((
            "jwt exp past",
            form(make_jwt(
                base_header(),
                base_payload(exp=now - 1),
            )),
        ))
        probes.append((
            "jwt exp too far",
            form(make_jwt(
                base_header(),
                base_payload(exp=now + 86400 * 365),
            )),
        ))
        probes.append((
            "jwt no jti",
            form(make_jwt(
                base_header(),
                {k: v for k, v in base_payload().items() if k != "jti"},
            )),
        ))

    # ========== Form-level probes ==========
    probes.append((
        "wrong grant type (password)",
        form("x.y.z", grant="password"),
    ))
    probes.append((
        "wrong client_assertion_type",
        form("x.y.z", at_type="wrong_type"),
    ))
    probes.append((
        "missing grant_type field",
        {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": "x.y.z",
        },
    ))

    return probes


async def map_token_endpoint_oracles(
    client: FHIRClient,
    token_url: str,
    valid_kid: str = "",
    valid_client_id: str = "",
    target_audience: str = "",
    result: ScanResult | None = None,
) -> OracleReport:
    """Run all JWT probes against a token endpoint and map distinct errors."""
    report = OracleReport(endpoint=token_url)
    probes = jwt_probe_generator(valid_kid, valid_client_id, target_audience)

    console.print(f"\n[bold]Mapping error oracles on {token_url}[/]")
    console.print(f"  Sending {len(probes)} probes...\n")

    # Use a direct httpx client to get proper form encoding
    async with httpx.AsyncClient(timeout=30) as hc:
        for label, form_data in probes:
            try:
                r = await hc.post(
                    token_url,
                    headers={"Accept": "application/json"},
                    data=form_data,  # httpx handles form encoding
                )
                body = r.text
                headers = dict(r.headers)
                error_text = extract_error_text(body, headers)
                probe = OracleProbe(
                    label=label,
                    status_code=r.status_code,
                    error_text=error_text,
                    body_prefix=body[:200],
                    response_headers={
                        k: v for k, v in headers.items()
                        if k.lower() in ("content-type", "www-authenticate")
                    },
                )
            except Exception as e:
                probe = OracleProbe(
                    label=label, status_code=0,
                    error_text=f"{type(e).__name__}: {str(e)[:150]}",
                )

            report.probes.append(probe)
            canonical = canonicalize_error(probe.error_text)
            report.error_to_probes.setdefault(canonical, []).append(label)

            # Use plain print (not Rich console) to avoid buffering issues
            # with large response bodies. Strip control chars for safety.
            safe_err = re.sub(
                r"[\x00-\x1f\x7f]", " ", probe.error_text[:120]
            ).strip()
            print(f"  [{probe.status_code}] {label}: {safe_err}", flush=True)

    report.distinct_errors = len(report.error_to_probes)
    all_errors = [p.error_text for p in report.probes]
    report.has_stack_trace_leak = detect_stack_trace_leak(all_errors)
    report.framework_hints = detect_framework(all_errors)

    _analyze_oracle_report(report, result)
    return report


def _analyze_oracle_report(report: OracleReport, result: ScanResult | None) -> None:
    """Summarize findings from an oracle mapping run and report them."""
    # Summary table
    console.print("\n[bold]Distinct error messages discovered:[/]\n")
    table = Table(show_header=True)
    table.add_column("Canonical Error", style="yellow", max_width=80)
    table.add_column("Probes", justify="right")
    table.add_column("Sample Probe", style="cyan")

    for canonical, probe_labels in sorted(
        report.error_to_probes.items(), key=lambda kv: len(kv[1])
    ):
        table.add_row(
            canonical[:80] or "(empty)",
            str(len(probe_labels)),
            probe_labels[0] if probe_labels else "",
        )
    console.print(table)

    console.print(f"\n  Total distinct errors: {report.distinct_errors}")
    console.print(f"  Framework hints: {report.framework_hints or 'none'}")
    console.print(f"  Stack trace leak: {report.has_stack_trace_leak}")

    if result is None:
        return

    # Finding 1: Many distinct error messages = validation order leak
    if report.distinct_errors >= 5:
        result.add_finding(Finding(
            title=f"JWT validation order leaked via {report.distinct_errors} distinct error messages",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                f"The endpoint returns {report.distinct_errors} distinct error messages "
                f"for different validation failures, enabling an attacker to map the "
                f"server's validation chain step by step. Each unique error corresponds "
                f"to a specific check — attackers can craft probes that pass earlier "
                f"checks to reach deeper validation logic."
            ),
            endpoint=report.endpoint,
            evidence={
                "distinct_error_messages": list(report.error_to_probes.keys()),
            },
            remediation=(
                "Return a uniform error response (e.g., 'Invalid request') for all "
                "malformed JWTs. Log detailed errors server-side only."
            ),
        ))

    # Finding 2: Stack trace leak
    if report.has_stack_trace_leak:
        result.add_finding(Finding(
            title="Stack trace / framework internals leaked in error responses",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                "Error responses contain strings that appear to be stack traces or "
                "framework internals, leaking information about the underlying language, "
                "framework, and code structure."
            ),
            endpoint=report.endpoint,
            evidence={
                "framework_hints": report.framework_hints,
                "sample_errors": [
                    p.error_text for p in report.probes
                    if any(
                        ind in p.error_text
                        for ind in ("Cannot invoke", "Traceback", "at java.")
                    )
                ][:5],
            },
        ))

    # Finding 3: 5xx errors indicating unhandled exceptions
    unhandled = [p for p in report.probes if p.status_code >= 500]
    if unhandled:
        unique_errs = set(canonicalize_error(p.error_text) for p in unhandled)
        result.add_finding(Finding(
            title=f"{len(unique_errs)} unhandled exception class(es) triggered",
            severity=Severity.MEDIUM,
            category=FindingCategory.CONFIG,
            description=(
                "Crafted probes triggered HTTP 5xx responses, indicating missing "
                "exception handling in the auth code path. Each distinct exception "
                "message represents a missing try/catch block."
            ),
            endpoint=report.endpoint,
            evidence={
                "unique_exceptions": sorted(unique_errs),
                "triggering_probes": [p.label for p in unhandled],
            },
            remediation=(
                "Add proper exception handling around JWT parsing, macaroon "
                "deserialization, UUID parsing, and field access. Return uniform 400 "
                "responses without leaking exception messages."
            ),
        ))


async def run_error_oracle_scan(
    client: FHIRClient,
    result: ScanResult,
    token_url: str,
    valid_kid: str = "",
    valid_client_id: str = "",
) -> OracleReport | None:
    """Convenience function for the CLI."""
    if not token_url:
        console.print("[yellow]No token URL provided — skipping[/]")
        return None
    return await map_token_endpoint_oracles(
        client, token_url,
        valid_kid=valid_kid,
        valid_client_id=valid_client_id,
        result=result,
    )
