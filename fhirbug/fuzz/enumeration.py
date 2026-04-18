"""Sequential ID / 401 vs 404 enumeration oracle testing.

Pattern discovered in CMS BCDA: sequential integer job IDs combined with a
401 (exists, not owned) vs 404 (doesn't exist) response discrepancy enabled
enumeration of every export job in the system.

This module provides reusable logic to detect and exploit this pattern on
any resource endpoint that takes an ID in the path.
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


@dataclass
class EnumerationResult:
    """Result of an ID enumeration probe."""
    endpoint: str
    probed_ids: list[str]
    existing_ids: list[str]    # returned 200, 202, 401 (exists-but-forbidden)
    missing_ids: list[str]     # returned 404
    errors: list[str]
    id_format: str             # "sequential_int", "uuid", "opaque", "unknown"
    has_oracle: bool           # True if 401 and 404 were both observed (leak!)
    lowest_existing: str | None = None
    highest_existing: str | None = None


def detect_id_format(sample_ids: list[str]) -> str:
    """Classify the format of observed resource IDs."""
    if not sample_ids:
        return "unknown"

    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
    )
    int_re = re.compile(r"^\d+$")

    if all(uuid_re.match(i) for i in sample_ids):
        return "uuid"
    if all(int_re.match(i) for i in sample_ids):
        # Check if they're sequential or at least close together
        ints = sorted(int(i) for i in sample_ids)
        if len(ints) >= 2:
            max_gap = max(ints[i + 1] - ints[i] for i in range(len(ints) - 1))
            if max_gap < 1000:
                return "sequential_int"
        return "sequential_int"  # integer but only one sample
    return "opaque"


async def probe_id_range(
    client: FHIRClient,
    endpoint_template: str,  # e.g., "{base}/api/v2/jobs/{id}"
    ids_to_probe: list[str],
    rate_limit_sleep: float = 0.2,
) -> EnumerationResult:
    """Probe a list of IDs and classify the responses."""
    result = EnumerationResult(
        endpoint=endpoint_template,
        probed_ids=list(ids_to_probe),
        existing_ids=[],
        missing_ids=[],
        errors=[],
        id_format="unknown",
        has_oracle=False,
    )

    existing_set = set()
    missing_set = set()
    seen_codes: dict[int, int] = {}

    for rid in ids_to_probe:
        url = endpoint_template.format(id=rid)
        try:
            r = await client.get(url)
            code = r.status_code
            seen_codes[code] = seen_codes.get(code, 0) + 1

            if code in (200, 202, 401, 403):
                existing_set.add(str(rid))
            elif code == 404:
                missing_set.add(str(rid))
            elif code >= 500:
                result.errors.append(f"{rid}: {code}")
        except httpx.HTTPError as e:
            result.errors.append(f"{rid}: {str(e)[:100]}")

        await asyncio.sleep(rate_limit_sleep)

    result.existing_ids = sorted(existing_set)
    result.missing_ids = sorted(missing_set)

    # Detect the oracle: did we see BOTH 401 AND 404?
    has_401 = 401 in seen_codes
    has_404 = 404 in seen_codes
    result.has_oracle = has_401 and has_404

    result.id_format = detect_id_format(result.existing_ids)
    if result.existing_ids and result.id_format == "sequential_int":
        try:
            int_existing = sorted(int(i) for i in result.existing_ids)
            result.lowest_existing = str(int_existing[0])
            result.highest_existing = str(int_existing[-1])
        except ValueError:
            pass

    return result


async def binary_search_lower_bound(
    client: FHIRClient,
    endpoint_template: str,
    known_existing: int,
    absolute_min: int = 1,
    rate_limit_sleep: float = 0.3,
) -> int | None:
    """Binary search to find the lowest integer ID that still exists."""
    if known_existing <= absolute_min:
        return absolute_min

    low, high = absolute_min, known_existing
    while high - low > 5:
        mid = (low + high) // 2
        url = endpoint_template.format(id=str(mid))
        try:
            r = await client.get(url)
            if r.status_code in (200, 202, 401, 403):
                high = mid
            else:
                low = mid
        except httpx.HTTPError:
            break
        await asyncio.sleep(rate_limit_sleep)

    return high


def generate_probe_ids(style: str, known_id: str | None = None) -> list[str]:
    """Generate a candidate probe list based on the suspected ID style."""
    if style == "sequential_int":
        base = int(known_id) if known_id and known_id.isdigit() else 1000
        # Wide-range sample across plausible ranges
        return [
            str(i) for i in [
                1, 2, 10, 100, 1000, 10000,
                max(1, base - 10), max(1, base - 5), max(1, base - 1),
                base,
                base + 1, base + 5, base + 10, base + 100,
                base + 1000, base * 10, base * 100,
                100000, 1000000,
            ]
        ]
    elif style == "uuid":
        base = known_id or "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        candidates = [
            base,  # baseline
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ]
        # Add variants of the base UUID
        if known_id and len(known_id) == 36:
            for offset in (1, 2, 10):
                last = known_id[-len(str(offset)):]
                try:
                    new_last = f"{(int(last, 16) + offset) & ((1 << (4 * len(last))) - 1):0{len(last)}x}"
                    candidates.append(known_id[:-len(last)] + new_last)
                except ValueError:
                    pass
        return candidates
    else:
        return ["0", "1", "100", "00000000-0000-0000-0000-000000000000"]


async def run_enumeration_scan(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    endpoints: list[str],
    known_id: str | None = None,
) -> None:
    """Run the full enumeration scan on a list of endpoint templates.

    Each endpoint template should contain `{id}` where the ID is substituted in.
    """
    console.print("\n[bold]Running ID enumeration oracle tests...[/]")

    for template in endpoints:
        console.print(f"\n  [cyan]Target:[/] {template}")

        # First pass: probe with a wide ID sample
        probe_list = generate_probe_ids("sequential_int", known_id)
        probe_list.extend(generate_probe_ids("uuid", known_id))

        enum_result = await probe_id_range(client, template, probe_list)

        console.print(f"    ID format (inferred): {enum_result.id_format}")
        console.print(f"    Existing: {len(enum_result.existing_ids)}")
        console.print(f"    Missing: {len(enum_result.missing_ids)}")
        console.print(f"    Oracle detected: {enum_result.has_oracle}")

        if enum_result.has_oracle:
            # Report the finding
            severity = Severity.MEDIUM
            if enum_result.id_format == "sequential_int":
                severity = Severity.HIGH  # sequential + oracle = trivially enumerable

            result.add_finding(Finding(
                title=(
                    f"Resource ID enumeration oracle on {template}: "
                    f"{enum_result.id_format} IDs with 401 vs 404 response discrepancy"
                ),
                severity=severity,
                category=FindingCategory.INFO_DISC,
                description=(
                    f"The endpoint returns HTTP 401 for IDs that exist but are not owned "
                    f"by the authenticated caller, and HTTP 404 for IDs that don't exist. "
                    f"This enables an attacker to map every resource ID in the system by "
                    f"iterating through the ID space. "
                    f"\n\nDetected ID format: {enum_result.id_format}. "
                    f"\nExisting IDs observed: {enum_result.existing_ids[:10]}"
                ),
                endpoint=template,
                evidence={
                    "id_format": enum_result.id_format,
                    "existing_ids": enum_result.existing_ids,
                    "missing_ids": enum_result.missing_ids[:20],
                    "lowest_existing": enum_result.lowest_existing,
                    "highest_existing": enum_result.highest_existing,
                    "has_oracle": True,
                },
                remediation=(
                    "Return identical HTTP responses (ideally 404) for both 'doesn't exist' "
                    "and 'exists but unauthorized' cases. Use UUIDs instead of sequential "
                    "integers for resource IDs."
                ),
            ))

        # If sequential, also run binary search to characterize the range
        if (
            enum_result.id_format == "sequential_int"
            and enum_result.lowest_existing
        ):
            lowest_int = int(enum_result.lowest_existing)
            if lowest_int > 1:
                console.print(f"    Binary searching lower boundary...")
                actual_lowest = await binary_search_lower_bound(
                    client, template, lowest_int
                )
                console.print(f"    Lower boundary: {actual_lowest}")
                if actual_lowest and actual_lowest != lowest_int:
                    enum_result.lowest_existing = str(actual_lowest)
