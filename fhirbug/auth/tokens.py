"""Token analysis — decode JWTs, check claims, detect weaknesses."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from rich.console import Console

from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


def decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Decode a JWT without signature verification to inspect claims."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    def _b64decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
        return header, payload
    except (ValueError, json.JSONDecodeError):
        return None


def analyze_token(token: str, result: ScanResult, endpoint: str) -> dict[str, Any]:
    """Analyze an access token for security issues."""
    analysis: dict[str, Any] = {"is_jwt": False, "claims": {}, "issues": []}

    decoded = decode_jwt_unverified(token)
    if decoded is None:
        analysis["is_jwt"] = False
        console.print("  [yellow]Token is not a JWT (opaque token)[/]")
        return analysis

    header, payload = decoded
    analysis["is_jwt"] = True
    analysis["header"] = header
    analysis["claims"] = payload

    console.print(f"  [green]JWT Algorithm:[/] {header.get('alg', 'none')}")
    console.print(f"  [green]JWT Issuer:[/] {payload.get('iss', 'not set')}")

    # alg: none
    if header.get("alg", "").lower() == "none":
        result.add_finding(Finding(
            title="JWT uses 'none' algorithm",
            severity=Severity.CRITICAL,
            category=FindingCategory.AUTHN,
            description=(
                "The access token JWT specifies alg=none, meaning no signature "
                "verification. An attacker can forge arbitrary tokens."
            ),
            endpoint=endpoint,
            evidence={"header": header},
        ))

    # Weak algorithms
    weak_algs = {"hs256", "hs384", "hs512"}
    if header.get("alg", "").lower() in weak_algs:
        result.add_finding(Finding(
            title=f"JWT uses symmetric algorithm ({header['alg']})",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHN,
            description=(
                "Symmetric HMAC algorithms share the signing key with all "
                "validators. If the secret is weak or leaked, tokens can be "
                "forged. RS256/ES256 are preferred."
            ),
            endpoint=endpoint,
            evidence={"algorithm": header["alg"]},
        ))

    # Token expiration
    exp = payload.get("exp")
    iat = payload.get("iat")
    now = int(time.time())

    if exp is None:
        result.add_finding(Finding(
            title="JWT has no expiration claim",
            severity=Severity.HIGH,
            category=FindingCategory.AUTHN,
            description="Access token has no 'exp' claim — it never expires.",
            endpoint=endpoint,
            evidence={"claims": list(payload.keys())},
        ))
    elif exp and iat:
        lifetime = exp - iat
        if lifetime > 86400:  # > 24 hours
            result.add_finding(Finding(
                title=f"JWT has long lifetime ({lifetime // 3600}h)",
                severity=Severity.MEDIUM,
                category=FindingCategory.AUTHN,
                description=(
                    f"Token lifetime is {lifetime // 3600} hours. Long-lived "
                    "tokens increase the window for stolen token abuse. "
                    "SMART recommends <=60 minutes."
                ),
                endpoint=endpoint,
                evidence={"iat": iat, "exp": exp, "lifetime_seconds": lifetime},
            ))

    if exp and exp < now:
        console.print("  [yellow]Token is expired[/]")

    # Scope analysis
    scope = payload.get("scope", payload.get("scp", ""))
    if isinstance(scope, list):
        scope = " ".join(scope)
    if scope:
        console.print(f"  [green]Scopes:[/] {scope}")
        scopes = scope.split()
        wildcard = [s for s in scopes if "*" in s]
        if wildcard:
            result.add_finding(Finding(
                title="Token contains wildcard scopes",
                severity=Severity.MEDIUM,
                category=FindingCategory.AUTHZ,
                description=(
                    f"Token has wildcard scopes: {wildcard}. Verify the server "
                    "enforces granular resource-level access despite the broad scope."
                ),
                endpoint=endpoint,
                evidence={"scopes": scopes, "wildcard_scopes": wildcard},
            ))

    # Patient context
    patient = payload.get("patient")
    if patient:
        console.print(f"  [green]Patient context:[/] {patient}")
        analysis["patient_context"] = patient

    # FHIR user
    fhir_user = payload.get("fhirUser")
    if fhir_user:
        console.print(f"  [green]FHIR User:[/] {fhir_user}")

    # Audience
    aud = payload.get("aud")
    if not aud:
        result.add_finding(Finding(
            title="JWT missing audience (aud) claim",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHN,
            description=(
                "No 'aud' claim in the token. Without audience restriction, "
                "the token could potentially be replayed against other FHIR servers."
            ),
            endpoint=endpoint,
            evidence={"claims": list(payload.keys())},
        ))

    return analysis
