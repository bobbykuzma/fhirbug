"""Scope boundary testing — verify the server enforces token scopes."""

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


async def test_scope_enforcement(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
    token_scopes: list[str],
) -> None:
    """Test whether the server actually enforces the scopes in the token.

    If the token has patient/Observation.read, can we still read Patient,
    Condition, etc.? Many servers issue broad tokens and don't enforce at
    the resource level.
    """
    if not token_scopes:
        console.print("[yellow]No scopes detected in token — skipping scope enforcement test[/]")
        return

    # Parse which resource types the token SHOULD have access to
    allowed_resources: set[str] = set()
    has_wildcard = False
    for scope in token_scopes:
        # Formats: patient/Patient.read, user/*.read, system/Observation.*
        parts = scope.split("/")
        if len(parts) != 2:
            continue
        resource_op = parts[1]
        resource = resource_op.split(".")[0]
        if resource == "*":
            has_wildcard = True
            break
        allowed_resources.add(resource)

    if has_wildcard:
        console.print("[yellow]Token has wildcard resource scope — scope boundary test not meaningful[/]")
        return

    if not allowed_resources:
        console.print("[yellow]Could not parse resource-level scopes[/]")
        return

    console.print(f"\n[bold]Testing scope enforcement...[/]")
    console.print(f"  Token allows: {sorted(allowed_resources)}")

    # Test resources NOT in the allowed set
    out_of_scope = [
        r for r in info.supported_resources
        if r in PHI_RESOURCES and r not in allowed_resources
    ][:10]  # test up to 10

    if not out_of_scope:
        console.print("  [yellow]All PHI resources are in scope — nothing to test[/]")
        return

    console.print(f"  Testing {len(out_of_scope)} out-of-scope resources...")

    violations: list[dict[str, Any]] = []

    for resource in out_of_scope:
        url = config.resource_url(resource)
        try:
            resp = await client.get(url, params={"_count": "1", "_summary": "count"})
            if resp.status_code == 200:
                body = resp.json()
                total = body.get("total", "unknown")
                violations.append({
                    "resource": resource,
                    "status": 200,
                    "total": total,
                })
                console.print(f"    [red]VIOLATION:[/] {resource} returned 200 (total={total})")
            else:
                console.print(f"    [green]OK:[/] {resource} returned {resp.status_code}")
        except httpx.HTTPError:
            pass

    if violations:
        result.add_finding(Finding(
            title=f"Scope enforcement bypass: {len(violations)} out-of-scope resources accessible",
            severity=Severity.HIGH,
            category=FindingCategory.AUTHZ,
            description=(
                "Resources outside the token's declared scopes returned data. "
                "The server is not enforcing SMART scopes at the resource level."
            ),
            endpoint=config.base_url,
            evidence={
                "token_scopes": token_scopes,
                "allowed_resources": sorted(allowed_resources),
                "violations": violations,
            },
        ))


async def test_patient_context_boundary(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
    patient_id: str,
) -> None:
    """Test whether patient-context tokens can access other patients' data.

    The token should restrict access to the specified patient. We try to
    access data without the patient filter to see if the server enforces it.
    """
    console.print(f"\n[bold]Testing patient context boundary (patient={patient_id})...[/]")

    resources_to_test = [
        r for r in info.supported_resources
        if r in PHI_RESOURCES
    ][:10]

    boundary_issues: list[dict[str, Any]] = []

    for resource in resources_to_test:
        url = config.resource_url(resource)

        # Search WITHOUT patient filter — if we get records for OTHER patients, it's a bypass
        try:
            resp = await client.get(url, params={"_count": "5"})
            if resp.status_code != 200:
                continue

            body = resp.json()
            entries = body.get("entry", [])

            for entry in entries:
                res = entry.get("resource", {})
                # Check if returned records belong to a different patient
                ref_patient = _extract_patient_ref(res)
                if ref_patient and ref_patient != patient_id and ref_patient != f"Patient/{patient_id}":
                    boundary_issues.append({
                        "resource": resource,
                        "expected_patient": patient_id,
                        "found_patient": ref_patient,
                        "resource_id": res.get("id", ""),
                    })
                    console.print(
                        f"    [red]BOUNDARY VIOLATION:[/] {resource} returned "
                        f"data for patient {ref_patient}"
                    )
                    break  # one violation per resource type is enough

        except httpx.HTTPError:
            pass

    if boundary_issues:
        result.add_finding(Finding(
            title=f"Patient context bypass: data from {len(boundary_issues)} other patients accessible",
            severity=Severity.CRITICAL,
            category=FindingCategory.AUTHZ,
            description=(
                "A patient-scoped token was able to retrieve records belonging "
                "to other patients. The server is not enforcing patient context "
                "compartment boundaries."
            ),
            endpoint=config.base_url,
            evidence={
                "patient_context": patient_id,
                "violations": boundary_issues,
            },
        ))
    else:
        console.print("  [green]Patient context boundary appears enforced.[/]")


def _extract_patient_ref(resource: dict[str, Any]) -> str | None:
    """Extract the patient reference from a FHIR resource."""
    # Direct subject/patient reference
    for field in ("subject", "patient"):
        ref = resource.get(field, {})
        if isinstance(ref, dict):
            return ref.get("reference", "")
    # If it IS a Patient resource
    if resource.get("resourceType") == "Patient":
        return f"Patient/{resource.get('id', '')}"
    return None
