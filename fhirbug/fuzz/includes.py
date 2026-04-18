"""_include and _revinclude abuse — data amplification and cross-resource exfil."""

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

# Common _include paths for data amplification
INCLUDE_PATHS = {
    "Patient": [
        "Patient:general-practitioner",
        "Patient:organization",
        "Patient:link",
    ],
    "Encounter": [
        "Encounter:patient",
        "Encounter:practitioner",
        "Encounter:location",
        "Encounter:service-provider",
        "Encounter:diagnosis",
    ],
    "Observation": [
        "Observation:patient",
        "Observation:subject",
        "Observation:performer",
        "Observation:encounter",
        "Observation:derived-from",
        "Observation:has-member",
    ],
    "MedicationRequest": [
        "MedicationRequest:patient",
        "MedicationRequest:requester",
        "MedicationRequest:medication",
        "MedicationRequest:encounter",
    ],
    "DiagnosticReport": [
        "DiagnosticReport:patient",
        "DiagnosticReport:performer",
        "DiagnosticReport:result",
        "DiagnosticReport:encounter",
    ],
    "Condition": [
        "Condition:patient",
        "Condition:encounter",
        "Condition:asserter",
    ],
    "Procedure": [
        "Procedure:patient",
        "Procedure:encounter",
        "Procedure:performer",
    ],
}

# _revinclude for pulling related records into a search
REVINCLUDE_PATHS = {
    "Patient": [
        "Observation:subject",
        "Condition:subject",
        "Encounter:subject",
        "MedicationRequest:subject",
        "Procedure:subject",
        "DiagnosticReport:subject",
        "AllergyIntolerance:patient",
        "Immunization:patient",
        "CarePlan:subject",
        "DocumentReference:subject",
    ],
}


async def test_include_amplification(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test _include for data amplification — pulling in related resources."""
    console.print("\n[bold]Testing _include amplification...[/]")

    for resource in info.supported_resources:
        includes = INCLUDE_PATHS.get(resource, [])
        if not includes:
            continue

        url = config.resource_url(resource)

        # Test individual includes
        for inc in includes:
            try:
                resp = await client.get(url, params={
                    "_include": inc,
                    "_count": "5",
                })
                if resp.status_code != 200:
                    continue

                body = resp.json()
                entries = body.get("entry", [])
                resource_types_returned = set()
                for entry in entries:
                    rt = entry.get("resource", {}).get("resourceType", "")
                    if rt:
                        resource_types_returned.add(rt)

                # Did we pull in additional resource types?
                extra_types = resource_types_returned - {resource}
                if extra_types:
                    console.print(
                        f"  [yellow]_include {inc} pulled in: {extra_types}[/]"
                    )

            except httpx.HTTPError:
                pass

        # Test _include wildcard — the big one
        try:
            resp = await client.get(url, params={
                "_include": "*",
                "_count": "5",
            })
            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("entry", [])
                types_returned = {
                    e.get("resource", {}).get("resourceType", "")
                    for e in entries
                }
                types_returned.discard("")

                if len(types_returned) > 1:
                    result.add_finding(Finding(
                        title=f"Wildcard _include supported on {resource}",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATA_LEAK,
                        description=(
                            f"_include=* is accepted on {resource} and returned "
                            f"{len(types_returned)} resource types: {types_returned}. "
                            "Wildcard includes pull ALL referenced resources in a "
                            "single query, enabling mass data exfiltration."
                        ),
                        endpoint=f"{url}?_include=*",
                        evidence={
                            "resource": resource,
                            "types_returned": sorted(types_returned),
                            "entry_count": len(entries),
                        },
                    ))

        except httpx.HTTPError:
            pass


async def test_revinclude_amplification(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test _revinclude for reverse data amplification."""
    console.print("\n[bold]Testing _revinclude amplification...[/]")

    for resource, revincludes in REVINCLUDE_PATHS.items():
        if resource not in info.supported_resources:
            continue

        url = config.resource_url(resource)

        # Test _revinclude wildcard
        try:
            resp = await client.get(url, params={
                "_revinclude": "*",
                "_count": "1",
            })
            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("entry", [])

                if len(entries) > 10:
                    result.add_finding(Finding(
                        title=f"Wildcard _revinclude on {resource} returns excessive data",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATA_LEAK,
                        description=(
                            f"_revinclude=* on {resource} with _count=1 returned "
                            f"{len(entries)} entries. Reverse includes pull ALL "
                            "resources that reference the matched records — a "
                            "single Patient search can return their entire chart."
                        ),
                        endpoint=f"{url}?_revinclude=*&_count=1",
                        evidence={"entry_count": len(entries)},
                    ))
                    console.print(
                        f"  [red]_revinclude=* on {resource} returned {len(entries)} entries![/]"
                    )

        except httpx.HTTPError:
            pass

        # Stack multiple _revinclude params — the "everything without $everything" trick
        try:
            params: dict[str, Any] = {"_count": "1"}
            # httpx handles repeated params via list of tuples
            multi_params = [("_count", "1")]
            for ri in revincludes[:5]:
                multi_params.append(("_revinclude", ri))

            resp = await client.request(
                "GET", url, params=dict(multi_params) if len(set(p[0] for p in multi_params)) == len(multi_params) else None,
            )
            # For repeated params, build URL manually
            param_str = "&".join(f"{k}={v}" for k, v in multi_params)
            full_url = f"{url}?{param_str}"
            resp = await client.get(full_url)

            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("entry", [])
                if len(entries) > 5:
                    types_returned = {
                        e.get("resource", {}).get("resourceType", "")
                        for e in entries
                    }
                    types_returned.discard("")
                    console.print(
                        f"  [yellow]Stacked _revinclude on {resource}: "
                        f"{len(entries)} entries, types={types_returned}[/]"
                    )

        except httpx.HTTPError:
            pass


async def test_include_iterate(
    client: FHIRClient,
    config: TargetConfig,
    info: EndpointInfo,
    result: ScanResult,
) -> None:
    """Test _include:iterate for recursive reference following."""
    console.print("\n[bold]Testing _include:iterate (recursive includes)...[/]")

    # Try recursive include from Encounter -> Patient -> Organization
    if "Encounter" in info.supported_resources:
        url = config.resource_url("Encounter")
        try:
            param_str = (
                "_include=Encounter:patient"
                "&_include:iterate=Patient:organization"
                "&_count=3"
            )
            resp = await client.get(f"{url}?{param_str}")
            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("entry", [])
                types = {
                    e.get("resource", {}).get("resourceType", "")
                    for e in entries
                }
                types.discard("")

                if len(types) > 2:
                    result.add_finding(Finding(
                        title="Recursive _include:iterate supported",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATA_LEAK,
                        description=(
                            "_include:iterate enables recursive reference "
                            "traversal. An attacker can chain includes to "
                            "traverse deep into the resource graph and pull "
                            "data several hops from the original query."
                        ),
                        endpoint=f"{url}?{param_str}",
                        evidence={"types_returned": sorted(types)},
                    ))
                    console.print(f"  [yellow]Recursive iterate returned types: {types}[/]")

        except httpx.HTTPError:
            pass
