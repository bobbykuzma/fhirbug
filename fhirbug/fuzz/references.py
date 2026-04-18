"""Reference traversal testing — cross-patient and cross-resource access."""

from __future__ import annotations

from typing import Any

import httpx
from rich.console import Console

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


async def test_direct_resource_access(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test whether resource IDs can be directly accessed (IDOR testing).

    Fetch a resource via search, extract references, then try to directly
    access referenced resources — some may be outside our authorization
    boundary.
    """
    console.print("\n[bold]Testing direct resource access (IDOR via references)...[/]")

    # First, get a sample resource to extract references from
    seed_resource = next(
        (r for r in ["Encounter", "Observation", "DiagnosticReport", "MedicationRequest"]
         if r in info.supported_resources),
        None,
    )
    if not seed_resource:
        console.print("  [yellow]No suitable seed resource available[/]")
        return

    url = config.resource_url(seed_resource)
    try:
        resp = await client.get(url, params={"_count": "3"})
        if resp.status_code != 200:
            console.print(f"  [yellow]Seed search returned {resp.status_code}[/]")
            return
    except httpx.HTTPError as e:
        console.print(f"  [yellow]Seed search failed: {e}[/]")
        return

    body = resp.json()
    entries = body.get("entry", [])
    if not entries:
        console.print("  [yellow]No entries returned from seed search[/]")
        return

    # Extract all references from returned resources
    references: set[str] = set()
    for entry in entries:
        _collect_references(entry.get("resource", {}), references)

    console.print(f"  Found {len(references)} references in {len(entries)} {seed_resource} entries")

    # Try to resolve each reference directly
    accessible_refs: list[dict[str, Any]] = []
    tested = 0

    for ref in sorted(references)[:30]:  # limit to 30
        # Parse reference: "Patient/123" -> resource_type=Patient, id=123
        parts = ref.split("/")
        if len(parts) < 2:
            continue
        ref_type = parts[-2]
        ref_id = parts[-1]

        if ref_type not in info.supported_resources:
            continue

        ref_url = config.resource_url(ref_type, ref_id)
        tested += 1

        try:
            resp = await client.get(ref_url)
            if resp.status_code == 200:
                accessible_refs.append({
                    "reference": ref,
                    "resource_type": ref_type,
                    "id": ref_id,
                    "status": 200,
                })
        except httpx.HTTPError:
            pass

    console.print(f"  Tested {tested} references, {len(accessible_refs)} accessible")

    # This is informational — the real issue is if we can access resources
    # outside our patient context (tested separately in auth/scopes.py)
    if accessible_refs:
        result.add_finding(Finding(
            title=f"Direct reference resolution: {len(accessible_refs)}/{tested} references accessible",
            severity=Severity.INFO,
            category=FindingCategory.AUTHZ,
            description=(
                "Referenced resources can be directly accessed by ID. This is "
                "normal behavior, but combined with patient context bypass, "
                "an attacker can traverse references to access arbitrary records."
            ),
            endpoint=config.base_url,
            evidence={
                "seed_resource": seed_resource,
                "total_references": len(references),
                "tested": tested,
                "accessible": len(accessible_refs),
                "sample": accessible_refs[:5],
            },
        ))


async def test_id_enumeration(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test whether resource IDs are predictable/enumerable.

    If IDs are sequential integers, an attacker can enumerate all records.
    If UUIDs, enumeration is impractical.
    """
    console.print("\n[bold]Testing resource ID predictability...[/]")

    for resource in ["Patient", "Encounter", "Observation"]:
        if resource not in info.supported_resources:
            continue

        url = config.resource_url(resource)
        try:
            resp = await client.get(url, params={"_count": "10", "_sort": "_id"})
            if resp.status_code != 200:
                continue

            body = resp.json()
            entries = body.get("entry", [])
            ids = [
                e.get("resource", {}).get("id", "")
                for e in entries
                if e.get("resource", {}).get("id")
            ]

            if not ids:
                continue

            # Check if IDs are sequential integers
            is_sequential = False
            try:
                int_ids = [int(i) for i in ids]
                if len(int_ids) > 1:
                    diffs = [int_ids[i + 1] - int_ids[i] for i in range(len(int_ids) - 1)]
                    if all(d == diffs[0] for d in diffs) and diffs[0] > 0:
                        is_sequential = True
            except ValueError:
                pass

            if is_sequential:
                result.add_finding(Finding(
                    title=f"Sequential integer IDs on {resource}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.AUTHZ,
                    description=(
                        f"{resource} uses sequential integer IDs, making enumeration "
                        "trivial. An attacker can iterate through all resource IDs "
                        "to discover and access records."
                    ),
                    endpoint=url,
                    evidence={
                        "sample_ids": ids[:5],
                        "id_pattern": "sequential_integer",
                    },
                ))
                console.print(f"  [red]{resource} uses sequential IDs: {ids[:5]}[/]")
            else:
                # Check if they look like UUIDs
                sample = ids[0]
                if len(sample) == 36 and sample.count("-") == 4:
                    console.print(f"  [green]{resource} uses UUIDs[/]")
                else:
                    console.print(f"  [yellow]{resource} ID format: {ids[0]}[/]")

        except httpx.HTTPError:
            pass


async def test_version_access(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test access to resource version history — may expose deleted/modified data."""
    console.print("\n[bold]Testing resource version history access...[/]")

    for resource in ["Patient", "Observation"]:
        if resource not in info.supported_resources:
            continue

        # Test instance-level _history
        url = config.resource_url(resource)
        try:
            # First get a resource ID
            resp = await client.get(url, params={"_count": "1"})
            if resp.status_code != 200:
                continue

            body = resp.json()
            entries = body.get("entry", [])
            if not entries:
                continue

            rid = entries[0].get("resource", {}).get("id", "")
            if not rid:
                continue

            # Try _history on this resource
            history_url = f"{url}/{rid}/_history"
            resp = await client.get(history_url, params={"_count": "10"})

            if resp.status_code == 200:
                body = resp.json()
                versions = body.get("entry", [])
                if len(versions) > 1:
                    result.add_finding(Finding(
                        title=f"Version history accessible on {resource}",
                        severity=Severity.LOW,
                        category=FindingCategory.INFO_DISC,
                        description=(
                            f"Resource history endpoint returns {len(versions)} "
                            f"versions of {resource}/{rid}. Historical versions may "
                            "contain data that was subsequently corrected or deleted."
                        ),
                        endpoint=history_url,
                        evidence={
                            "resource": resource,
                            "id": rid,
                            "version_count": len(versions),
                        },
                    ))
                    console.print(f"  [yellow]{resource}/{rid}/_history: {len(versions)} versions[/]")

        except httpx.HTTPError:
            pass

    # Test type-level _history — can we see ALL changes?
    try:
        resp = await client.get(
            f"{config.base_url.rstrip('/')}/Patient/_history",
            params={"_count": "1"},
        )
        if resp.status_code == 200:
            body = resp.json()
            total = body.get("total")
            result.add_finding(Finding(
                title="Type-level _history accessible on Patient",
                severity=Severity.MEDIUM,
                category=FindingCategory.DATA_LEAK,
                description=(
                    f"Patient/_history endpoint is accessible (total={total}). "
                    "Type-level history returns all changes across all patients, "
                    "which is a broad data access vector."
                ),
                endpoint=f"{config.base_url}/Patient/_history",
                evidence={"total": total},
            ))
            console.print(f"  [red]Patient/_history accessible (total={total})[/]")
    except httpx.HTTPError:
        pass


def _collect_references(obj: Any, refs: set[str], depth: int = 0) -> None:
    """Recursively collect all FHIR references from a resource."""
    if depth > 10:
        return
    if isinstance(obj, dict):
        if "reference" in obj and isinstance(obj["reference"], str):
            ref = obj["reference"]
            # Only collect relative references (Resource/id format)
            if "/" in ref and not ref.startswith("http"):
                refs.add(ref)
        for v in obj.values():
            _collect_references(v, refs, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_references(item, refs, depth + 1)
