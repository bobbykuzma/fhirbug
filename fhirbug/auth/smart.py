"""SMART on FHIR authentication flow testing."""

from __future__ import annotations

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


async def test_token_endpoint(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Probe the token endpoint for misconfigurations."""
    token_endpoint = (
        info.smart_config.get("token_endpoint")
        or info.security.get("extensions", {}).get("token", "")
    )
    if not token_endpoint:
        console.print("[yellow]No token endpoint discovered — skipping auth flow tests[/]")
        return

    console.print(f"\n[bold]Testing token endpoint:[/] {token_endpoint}")

    # Test 1: Invalid grant_type
    try:
        resp = await client.request(
            "POST", token_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            raw_body="grant_type=invalid_grant",
        )
        if resp.status_code == 200:
            result.add_finding(Finding(
                title="Token endpoint accepted invalid grant_type",
                severity=Severity.HIGH,
                category=FindingCategory.AUTHN,
                description=(
                    "The token endpoint returned 200 for an invalid grant_type. "
                    "This suggests weak input validation on the token endpoint."
                ),
                endpoint=token_endpoint,
                evidence={"status": resp.status_code, "body": resp.text[:500]},
            ))
        else:
            console.print(f"  [green]Invalid grant_type correctly rejected ({resp.status_code})[/]")
    except httpx.HTTPError:
        pass

    # Test 2: client_credentials without client auth
    try:
        resp = await client.request(
            "POST", token_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            raw_body="grant_type=client_credentials&scope=system/*.read",
        )
        if resp.status_code == 200:
            result.add_finding(Finding(
                title="client_credentials grant issued token without client authentication",
                severity=Severity.CRITICAL,
                category=FindingCategory.AUTHN,
                description=(
                    "Token endpoint issued a system-level token via "
                    "client_credentials grant without requiring client "
                    "authentication (no client_id/secret or JWT assertion). "
                    "This allows any attacker to get system-level access."
                ),
                endpoint=token_endpoint,
                evidence={"status": resp.status_code, "body": resp.text[:500]},
            ))
        else:
            console.print(f"  [green]Unauthenticated client_credentials rejected ({resp.status_code})[/]")
    except httpx.HTTPError:
        pass

    # Test 3: Check for verbose error messages
    try:
        resp = await client.request(
            "POST", token_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            raw_body="grant_type=authorization_code&code=invalid_code_12345&redirect_uri=https://evil.example.com/callback",
        )
        body = resp.text.lower()
        info_leaks = []
        for indicator in ["stack trace", "exception", "sql", "internal server",
                          "debug", "traceback", "file:", "line "]:
            if indicator in body:
                info_leaks.append(indicator)

        if info_leaks:
            result.add_finding(Finding(
                title="Token endpoint leaks internal information in error responses",
                severity=Severity.MEDIUM,
                category=FindingCategory.INFO_DISC,
                description=(
                    "Error responses from the token endpoint contain internal "
                    "details that could aid exploitation."
                ),
                endpoint=token_endpoint,
                evidence={
                    "indicators": info_leaks,
                    "response_snippet": resp.text[:500],
                },
            ))
    except httpx.HTTPError:
        pass


async def test_registration_endpoint(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test dynamic client registration if available."""
    reg_endpoint = info.smart_config.get("registration_endpoint")
    if not reg_endpoint:
        return

    console.print(f"\n[bold]Testing dynamic client registration:[/] {reg_endpoint}")

    # Attempt to register a client
    registration_request = {
        "client_name": "FHIR Security Test Client",
        "redirect_uris": ["https://localhost:9999/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "patient/*.read launch/patient openid fhirUser",
        "token_endpoint_auth_method": "none",
    }

    try:
        resp = await client.post(
            reg_endpoint,
            json_body=registration_request,
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code in (200, 201):
            try:
                body = resp.json()
            except (ValueError, Exception):
                body = {}

            # If we got a client_id back, registration was truly open
            if body.get("client_id"):
                result.add_finding(Finding(
                    title="Open dynamic client registration — new client registered successfully",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.AUTHN,
                    description=(
                        "Dynamic client registration is open without pre-authorization. "
                        "An attacker can register arbitrary OAuth clients and request "
                        "broad scopes. The registered client_id is included in evidence."
                    ),
                    endpoint=reg_endpoint,
                    evidence={
                        "client_id": body.get("client_id", ""),
                        "granted_scope": body.get("scope", ""),
                        "response": {
                            k: v for k, v in body.items()
                            if k not in ("client_secret", "registration_access_token")
                        },
                    },
                    remediation=(
                        "Require pre-authorization or admin approval for client "
                        "registration. Implement client vetting per SMART App Launch IG."
                    ),
                ))
            else:
                # Got 200/201 but response isn't a registration success
                console.print(
                    f"  [yellow]Registration endpoint returned {resp.status_code} "
                    f"but no client_id — likely a UI/portal page[/]"
                )
                result.add_finding(Finding(
                    title="Registration endpoint returns 200 but is not RFC 7591 compliant",
                    severity=Severity.INFO,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The registration endpoint returned 200 to a POST but did not "
                        "return an RFC 7591 client registration response. It may be a "
                        "manual portal or require authentication to register."
                    ),
                    endpoint=reg_endpoint,
                    evidence={
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "response_snippet": resp.text[:500],
                    },
                ))
        else:
            console.print(f"  [green]Registration rejected ({resp.status_code})[/]")

    except httpx.HTTPError as e:
        console.print(f"  [yellow]Registration request failed: {e}[/]")
