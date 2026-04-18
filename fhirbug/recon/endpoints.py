"""Endpoint discovery — probe for accessible resources and open endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from fhirbug.core.client import FHIRClient
from fhirbug.core.config import PHI_RESOURCES, TargetConfig
from fhirbug.core.models import (
    EndpointInfo,
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


async def probe_resource(
    client: FHIRClient,
    config: TargetConfig,
    resource_type: str,
) -> dict[str, Any]:
    """Probe a single resource endpoint and return access info."""
    url = config.resource_url(resource_type)
    result: dict[str, Any] = {
        "resource": resource_type,
        "url": url,
        "search_accessible": False,
        "status_code": None,
        "record_count": None,
        "error": None,
    }

    try:
        # Try search with _count=1 to minimize data transfer
        resp = await client.get(url, params={"_count": "1", "_summary": "count"})
        result["status_code"] = resp.status_code

        if resp.status_code == 200:
            result["search_accessible"] = True
            body = resp.json()
            result["record_count"] = body.get("total")

    except httpx.HTTPError as e:
        result["error"] = str(e)

    return result


async def probe_resource_no_auth(
    client: FHIRClient,
    config: TargetConfig,
    resource_type: str,
) -> dict[str, Any]:
    """Probe a resource endpoint WITHOUT authorization headers."""
    url = config.resource_url(resource_type)
    result: dict[str, Any] = {
        "resource": resource_type,
        "url": url,
        "accessible_without_auth": False,
        "status_code": None,
        "error": None,
    }

    try:
        resp = await client.get(
            url,
            params={"_count": "1", "_summary": "count"},
            headers={"Authorization": "", "Accept": "application/fhir+json"},
        )
        result["status_code"] = resp.status_code
        if resp.status_code == 200:
            result["accessible_without_auth"] = True

    except httpx.HTTPError as e:
        result["error"] = str(e)

    return result


async def run_endpoint_discovery(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Probe all known resource endpoints for accessibility."""
    resources = info.supported_resources or PHI_RESOURCES

    console.print(f"\n[bold]Probing {len(resources)} resource endpoints...[/]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Probing endpoints", total=len(resources))

        # Probe with auth
        auth_results = []
        for resource in resources:
            probe = await probe_resource(client, config, resource)
            auth_results.append(probe)
            progress.advance(task)

    accessible = [r for r in auth_results if r["search_accessible"]]
    console.print(
        f"  [green]{len(accessible)}/{len(resources)}[/] resources accessible "
        f"via search"
    )

    # Report accessible PHI resources
    phi_accessible = [
        r for r in accessible if r["resource"] in PHI_RESOURCES
    ]
    if phi_accessible:
        result.add_finding(Finding(
            title=f"{len(phi_accessible)} PHI resource types accessible via search",
            severity=Severity.INFO,
            category=FindingCategory.DATA_LEAK,
            description=(
                "The following PHI-containing resource types returned 200 on "
                "search. This is expected with valid auth, but verify scope "
                "enforcement limits results to authorized records only."
            ),
            endpoint=info.base_url,
            evidence={
                "phi_resources": [
                    {
                        "resource": r["resource"],
                        "record_count": r["record_count"],
                    }
                    for r in phi_accessible
                ]
            },
        ))

    # Resources with large record counts — high value targets
    large_resources = [
        r for r in accessible
        if r["record_count"] is not None and r["record_count"] > 10000
    ]
    if large_resources:
        result.add_finding(Finding(
            title="Resource types with large record populations detected",
            severity=Severity.INFO,
            category=FindingCategory.DATA_LEAK,
            description=(
                "Some resources report large total counts. Combined with weak "
                "pagination controls, an attacker could exfiltrate large datasets."
            ),
            endpoint=info.base_url,
            evidence={
                "large_resources": [
                    {"resource": r["resource"], "count": r["record_count"]}
                    for r in large_resources
                ]
            },
        ))

    # Now test without auth if we have a token (otherwise we already are no-auth)
    if config.access_token:
        console.print("\n[bold]Testing unauthenticated access...[/]")
        no_auth_results = []
        for resource in [r["resource"] for r in accessible[:20]]:
            probe = await probe_resource_no_auth(client, config, resource)
            no_auth_results.append(probe)

        open_resources = [r for r in no_auth_results if r["accessible_without_auth"]]
        if open_resources:
            sev = Severity.CRITICAL if any(
                r["resource"] in PHI_RESOURCES for r in open_resources
            ) else Severity.HIGH

            result.add_finding(Finding(
                title=f"{len(open_resources)} resources accessible WITHOUT authentication",
                severity=sev,
                category=FindingCategory.AUTHN,
                description=(
                    "Resources returned 200 with no Authorization header. "
                    "This means unauthenticated access to FHIR data is possible."
                ),
                endpoint=info.base_url,
                evidence={
                    "open_resources": [r["resource"] for r in open_resources]
                },
            ))
        else:
            console.print("  [green]All tested resources require authentication.[/]")
