"""SMART on FHIR configuration discovery and analysis."""

from __future__ import annotations

from urllib.parse import urljoin

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

SMART_WELL_KNOWN_PATH = "/.well-known/smart-configuration"


async def fetch_smart_config(
    client: FHIRClient, config: TargetConfig
) -> dict | None:
    """Fetch .well-known/smart-configuration."""
    url = urljoin(config.base_url.rstrip("/") + "/", ".well-known/smart-configuration")
    console.print(f"[cyan]GET[/] {url}")
    return await client.get_json(url)


def analyze_smart_config(
    smart: dict, info: EndpointInfo, result: ScanResult
) -> None:
    """Analyze SMART configuration for security issues."""
    base = info.base_url
    well_known_url = f"{base}/.well-known/smart-configuration"

    info.smart_config = smart

    # Check grant types
    grant_types = smart.get("grant_types_supported", [])

    if "client_credentials" in grant_types:
        result.add_finding(Finding(
            title="Backend services (client_credentials) grant supported",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHN,
            description=(
                "client_credentials grant is supported, used for system-level "
                "access (Bulk Data). Verify that client registration requires "
                "proper vetting and that issued tokens are appropriately scoped."
            ),
            endpoint=well_known_url,
            evidence={"grant_types": grant_types},
        ))

    if "password" in grant_types:
        result.add_finding(Finding(
            title="Resource Owner Password Credentials grant supported",
            severity=Severity.HIGH,
            category=FindingCategory.AUTHN,
            description=(
                "ROPC grant is supported — this is deprecated by OAuth 2.1 and "
                "enables credential stuffing / brute-force attacks against the "
                "token endpoint."
            ),
            endpoint=well_known_url,
            evidence={"grant_types": grant_types},
        ))

    # Check scopes
    scopes = smart.get("scopes_supported", [])

    wildcard_scopes = [s for s in scopes if "*" in s]
    if wildcard_scopes:
        result.add_finding(Finding(
            title="Wildcard SMART scopes supported",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHZ,
            description=(
                f"Wildcard scopes are advertised: {wildcard_scopes}. "
                "A client granted patient/*.read gets access to ALL resource "
                "types for a patient — test whether granular scope enforcement "
                "is actually applied."
            ),
            endpoint=well_known_url,
            evidence={"wildcard_scopes": wildcard_scopes},
        ))

    system_scopes = [s for s in scopes if s.startswith("system/")]
    if system_scopes:
        result.add_finding(Finding(
            title="System-level SMART scopes advertised",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHZ,
            description=(
                f"System-level scopes: {system_scopes}. These bypass patient "
                "context and grant access to all records. Verify that only "
                "authorized backend services can obtain these scopes."
            ),
            endpoint=well_known_url,
            evidence={"system_scopes": system_scopes},
        ))

    # Check code challenge methods — PKCE support
    code_challenge = smart.get("code_challenge_methods_supported", [])
    if code_challenge and "S256" not in code_challenge:
        result.add_finding(Finding(
            title="PKCE S256 not supported",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHN,
            description=(
                "The authorization server does not support S256 code challenge. "
                "This weakens protection against authorization code interception."
            ),
            endpoint=well_known_url,
            evidence={"code_challenge_methods": code_challenge},
        ))

    if not code_challenge:
        result.add_finding(Finding(
            title="No PKCE support advertised",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTHN,
            description=(
                "No code_challenge_methods_supported field in SMART config. "
                "PKCE is required by SMART App Launch v2 to prevent authorization "
                "code interception attacks."
            ),
            endpoint=well_known_url,
            evidence={"code_challenge_methods": []},
        ))

    # Token introspection / revocation
    if smart.get("token_endpoint_auth_methods_supported"):
        auth_methods = smart["token_endpoint_auth_methods_supported"]
        if "none" in auth_methods:
            result.add_finding(Finding(
                title="Token endpoint accepts unauthenticated clients",
                severity=Severity.HIGH,
                category=FindingCategory.AUTHN,
                description=(
                    "Token endpoint auth method 'none' is supported, meaning "
                    "public clients can obtain tokens without client authentication. "
                    "Combined with weak scope enforcement, this is dangerous."
                ),
                endpoint=well_known_url,
                evidence={"auth_methods": auth_methods},
            ))

    # Report all discovered endpoints
    endpoints_found = {}
    for key in [
        "authorization_endpoint", "token_endpoint", "introspection_endpoint",
        "revocation_endpoint", "registration_endpoint", "management_endpoint",
    ]:
        if smart.get(key):
            endpoints_found[key] = smart[key]

    if endpoints_found:
        console.print("  [green]SMART endpoints:[/]")
        for k, v in endpoints_found.items():
            console.print(f"    {k}: {v}")

    # Dynamic registration — can we register our own client?
    if smart.get("registration_endpoint"):
        result.add_finding(Finding(
            title="Dynamic client registration endpoint exposed",
            severity=Severity.HIGH,
            category=FindingCategory.AUTHN,
            description=(
                "Dynamic client registration is available. An attacker may be "
                "able to register a new OAuth client and request broad scopes. "
                "Test whether registration is open or requires pre-authorization."
            ),
            endpoint=smart["registration_endpoint"],
            evidence={"registration_endpoint": smart["registration_endpoint"]},
        ))


async def run_smart_recon(
    client: FHIRClient, config: TargetConfig, info: EndpointInfo, result: ScanResult
) -> None:
    """Full SMART configuration recon."""
    smart = await fetch_smart_config(client, config)
    if smart is None:
        result.add_finding(Finding(
            title="No .well-known/smart-configuration found",
            severity=Severity.INFO,
            category=FindingCategory.CONFIG,
            description=(
                "SMART configuration endpoint is not available. The server may "
                "not implement SMART on FHIR, or the endpoint may be at a "
                "different path. Check CapabilityStatement security extensions "
                "for OAuth URLs."
            ),
            endpoint=f"{config.base_url}/.well-known/smart-configuration",
        ))
        return

    analyze_smart_config(smart, info, result)
