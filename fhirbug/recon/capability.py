"""CapabilityStatement parser — extract the full attack surface from /metadata."""

from __future__ import annotations

from typing import Any

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


async def fetch_capability(
    client: FHIRClient, config: TargetConfig
) -> dict[str, Any] | None:
    """Fetch the CapabilityStatement from /metadata."""
    url = config.metadata_url()
    console.print(f"[cyan]GET[/] {url}")
    return await client.get_json(url)


def parse_capability(
    raw: dict[str, Any], base_url: str
) -> EndpointInfo:
    """Parse a CapabilityStatement into structured EndpointInfo."""
    info = EndpointInfo(base_url=base_url)
    info.raw_capability = raw

    info.fhir_version = raw.get("fhirVersion", "unknown")

    software = raw.get("software", {})
    info.software_name = software.get("name", "")
    info.software_version = software.get("version", "")

    # Vendor heuristics
    name_lower = info.software_name.lower()
    if "epic" in name_lower:
        info.vendor = "Epic"
    elif "cerner" in name_lower or "millennium" in name_lower or "oracle" in name_lower:
        info.vendor = "Oracle Health (Cerner)"
    elif "meditech" in name_lower:
        info.vendor = "MEDITECH"
    elif "athena" in name_lower:
        info.vendor = "athenahealth"
    elif "eclinical" in name_lower or "healow" in name_lower:
        info.vendor = "eClinicalWorks"
    elif "nextgen" in name_lower:
        info.vendor = "NextGen"
    elif "greenway" in name_lower:
        info.vendor = "Greenway Health"
    elif "drchrono" in name_lower:
        info.vendor = "DrChrono"
    elif "modmed" in name_lower or "ema" in name_lower:
        info.vendor = "ModMed"
    elif "veradigm" in name_lower or "allscripts" in name_lower:
        info.vendor = "Veradigm"
    elif "hapi" in name_lower:
        info.vendor = "HAPI FHIR (open source)"
    elif "smile" in name_lower:
        info.vendor = "Smile CDR"

    # Security section
    rest_list = raw.get("rest", [])
    for rest in rest_list:
        security = rest.get("security", {})
        info.security = {
            "cors": security.get("cors", None),
            "services": [
                coding.get("code", "")
                for svc in security.get("service", [])
                for coding in svc.get("coding", [])
            ],
            "description": security.get("description", ""),
            "extensions": _extract_security_extensions(security),
        }

        # Resources
        for resource in rest.get("resource", []):
            rtype = resource.get("type", "")
            if rtype:
                info.supported_resources.append(rtype)

                # Interactions per resource
                interactions = [
                    i.get("code", "") for i in resource.get("interaction", [])
                ]
                info.interactions[rtype] = interactions

                # Search params per resource
                sparams = [
                    p.get("name", "") for p in resource.get("searchParam", [])
                ]
                if sparams:
                    info.search_params[rtype] = sparams

        # Server-level operations
        for op in rest.get("operation", []):
            info.operations.append(op.get("name", ""))

        # Server-level interactions
        server_interactions = [
            i.get("code", "") for i in rest.get("interaction", [])
        ]
        if server_interactions:
            info.interactions["_server"] = server_interactions

    return info


def _extract_security_extensions(security: dict[str, Any]) -> dict[str, str]:
    """Pull SMART OAuth URLs from security extensions."""
    urls: dict[str, str] = {}
    for ext in security.get("extension", []):
        if "oauth" in ext.get("url", "").lower():
            for inner in ext.get("extension", []):
                url_key = inner.get("url", "")
                url_val = inner.get("valueUri", "") or inner.get("valueUrl", "")
                if url_key and url_val:
                    urls[url_key] = url_val
    return urls


def analyze_capability(
    info: EndpointInfo, result: ScanResult
) -> None:
    """Generate findings from the parsed CapabilityStatement."""
    base = info.base_url

    # Check for version disclosure
    if info.software_version:
        result.add_finding(Finding(
            title="Software version disclosed in CapabilityStatement",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                f"Server identifies as {info.software_name} {info.software_version}. "
                "Version info aids targeted exploit research."
            ),
            endpoint=f"{base}/metadata",
            evidence={
                "software_name": info.software_name,
                "software_version": info.software_version,
            },
        ))

    # CORS enabled — broader attack surface from browser-based attacks
    if info.security.get("cors") is True:
        result.add_finding(Finding(
            title="CORS enabled on FHIR endpoint",
            severity=Severity.INFO,
            category=FindingCategory.CONFIG,
            description=(
                "CORS is enabled, meaning browser-based applications can make "
                "cross-origin requests. Check Access-Control-Allow-Origin for "
                "overly permissive configuration."
            ),
            endpoint=f"{base}/metadata",
            evidence={"cors": True},
        ))

    # No security services defined
    if not info.security.get("services"):
        result.add_finding(Finding(
            title="No security services declared in CapabilityStatement",
            severity=Severity.HIGH,
            category=FindingCategory.AUTHN,
            description=(
                "The CapabilityStatement does not declare any security services "
                "(e.g., SMART-on-FHIR, OAuth). This may indicate the endpoint "
                "is unauthenticated or security metadata is incomplete."
            ),
            endpoint=f"{base}/metadata",
            evidence={"security_services": []},
        ))

    # Check for dangerous interactions
    for rtype, interactions in info.interactions.items():
        if rtype == "_server":
            continue
        write_ops = [i for i in interactions if i in ("create", "update", "delete", "patch")]
        if write_ops:
            result.add_finding(Finding(
                title=f"Write operations available on {rtype}",
                severity=Severity.MEDIUM,
                category=FindingCategory.AUTHZ,
                description=(
                    f"Resource {rtype} supports write operations: {write_ops}. "
                    "Verify these require appropriate authorization."
                ),
                endpoint=f"{base}/{rtype}",
                evidence={
                    "resource": rtype,
                    "write_interactions": write_ops,
                },
            ))

    # Check for $everything operation — mass data exfil vector
    if "$everything" in info.operations or "everything" in info.operations:
        result.add_finding(Finding(
            title="$everything operation exposed at server level",
            severity=Severity.HIGH,
            category=FindingCategory.DATA_LEAK,
            description=(
                "The $everything operation returns all data associated with a "
                "resource. If authorization is weak, this is a one-call PHI "
                "exfiltration vector."
            ),
            endpoint=f"{base}/$everything",
            evidence={"operation": "$everything"},
        ))

    # Check for $export (Bulk Data) — mass export
    if "$export" in info.operations or "export" in info.operations:
        result.add_finding(Finding(
            title="Bulk Data $export operation exposed",
            severity=Severity.HIGH,
            category=FindingCategory.DATA_LEAK,
            description=(
                "Bulk Data $export can dump entire resource populations. "
                "Requires backend-services auth (client_credentials grant) — "
                "test whether this is enforced."
            ),
            endpoint=f"{base}/$export",
            evidence={"operation": "$export"},
        ))

    # Check for $graphql
    if "$graphql" in info.operations or "graphql" in info.operations:
        result.add_finding(Finding(
            title="GraphQL operation exposed on FHIR server",
            severity=Severity.MEDIUM,
            category=FindingCategory.INFO_DISC,
            description=(
                "GraphQL enables flexible queries that can traverse resource "
                "relationships in a single request. Test for introspection, "
                "unbounded queries, and authorization bypass via nested resolution."
            ),
            endpoint=f"{base}/$graphql",
            evidence={"operation": "$graphql"},
        ))

    # Large number of resources — wider attack surface
    if len(info.supported_resources) > 50:
        result.add_finding(Finding(
            title=f"Large attack surface: {len(info.supported_resources)} resource types exposed",
            severity=Severity.INFO,
            category=FindingCategory.CONFIG,
            description=(
                "A large number of resource types are exposed. Many may not "
                "be needed for the stated use case, increasing attack surface."
            ),
            endpoint=f"{base}/metadata",
            evidence={
                "resource_count": len(info.supported_resources),
                "resources": info.supported_resources,
            },
        ))


async def run_capability_recon(
    client: FHIRClient, config: TargetConfig, result: ScanResult
) -> EndpointInfo | None:
    """Full capability recon: fetch, parse, analyze."""
    raw = await fetch_capability(client, config)
    if raw is None:
        result.add_error("Failed to fetch CapabilityStatement from /metadata")
        return None

    if raw.get("resourceType") != "CapabilityStatement":
        result.add_error(
            f"/metadata returned resourceType={raw.get('resourceType')!r}, "
            "expected CapabilityStatement"
        )
        return None

    info = parse_capability(raw, config.base_url)
    analyze_capability(info, result)

    console.print(f"  [green]FHIR version:[/] {info.fhir_version}")
    console.print(f"  [green]Software:[/] {info.software_name} {info.software_version}")
    console.print(f"  [green]Vendor (guess):[/] {info.vendor or 'unknown'}")
    console.print(f"  [green]Resources:[/] {len(info.supported_resources)}")
    console.print(f"  [green]Operations:[/] {info.operations or 'none declared'}")
    console.print(f"  [green]Security services:[/] {info.security.get('services', [])}")

    return info
