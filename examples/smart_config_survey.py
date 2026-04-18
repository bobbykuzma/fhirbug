"""Run the SMART-on-FHIR discovery survey across every stack we've tested.

Writes:
  - jwt_fuzz_evidence/smart_survey/<target>_config.json, raw captured configs
  - jwt_fuzz_evidence/smart_survey/matrix.json, normalized cross-vendor matrix
  - Prints a markdown comparison table to stdout
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fhirbug.auth.smart_scanner import survey_targets, to_matrix_row


# Customize this list for your engagement. Each entry is a {name, fhir_base} pair.
# The entries below are public reference / sandbox endpoints commonly used in
# healthcare interop research, verify each is within your authorized scope
# before probing. For production commercial endpoints (Epic customer deployments,
# payer FHIR APIs, aggregators, etc.), consult the vendor's VDP / BBP scope first.
#
# Tip: for per-engagement reuse, move this list into a separate TARGETS.json file
# and load it at runtime.
TARGETS = [
    # EHR vendor public sandboxes
    {"name": "Epic (sandbox)", "fhir_base": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"},
    {"name": "HAPI (public reference)", "fhir_base": "https://hapi.fhir.org/baseR4"},

    # CMS programs, public sandboxes, within CMS Bugcrowd BBP safe-harbor scope for registered researchers
    {"name": "CMS Blue Button 2.0", "fhir_base": "https://sandbox.bluebutton.cms.gov/v2/fhir"},
    {"name": "CMS BCDA", "fhir_base": "https://sandbox.bcda.cms.gov/api/v2"},
    {"name": "CMS AB2D", "fhir_base": "https://sandbox.ab2d.cms.gov/api/v1/fhir"},
    {"name": "CMS DPC", "fhir_base": "https://sandbox.dpc.cms.gov/api/v1"},

    # Add your own targets below:
    # {"name": "My Vendor Sandbox", "fhir_base": "https://fhir.example.com/R4"},
]


async def main() -> None:
    out_dir = Path(__file__).parent / "jwt_fuzz_evidence" / "smart_survey"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Running SMART config survey across {len(TARGETS)} targets..")
    results = await survey_targets(TARGETS, concurrency=4)

    # Dump raw configs
    for r in results:
        safe = r.target.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
        (out_dir / f"{safe}_config.json").write_text(
            json.dumps({
                "target": r.target,
                "source_url": r.source_url,
                "http_status": r.http_status,
                "fetched": r.fetched,
                "error_note": r.error_note,
                "raw_config": r.raw_config,
            }, indent=2, default=str)
        )

    # Build the matrix
    matrix = [to_matrix_row(r) for r in results]
    (out_dir / "matrix.json").write_text(json.dumps(matrix, indent=2))

    # Print markdown table
    print("\n## SMART Config Survey. Cross-Vendor Matrix\n")
    print("| Target | Fetched | Source | PKCE-S256 | PKCE-plain | priv_key_jwt | OIDC | auth_code | client_creds | refresh | v1 | v2 | #scopes | #caps |")
    print("|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---:|---:|")
    for row in matrix:
        def yn(b): return "✓" if b else ", "
        def risk(b): return "⚠" if b else ", "
        print(
            f"| {row['target']} | "
            f"{yn(row['fetched'])} | "
            f"{row['source']} | "
            f"{yn(row['PKCE_S256'])} | "
            f"{risk(row['PKCE_plain'])} | "
            f"{yn(row['private_key_jwt'])} | "
            f"{yn(row['openid'])} | "
            f"{yn(row['auth_code'])} | "
            f"{yn(row['client_creds'])} | "
            f"{yn(row['refresh'])} | "
            f"{yn(row['smart_v1'])} | "
            f"{yn(row['smart_v2'])} | "
            f"{row['n_scopes']} | "
            f"{row['n_caps']} |"
        )

    # Outliers
    print("\n## Posture outliers\n")
    unfetched = [r for r in matrix if not r["fetched"]]
    print(f"- {len(unfetched)} targets with no reachable SMART config: {[r['target'] for r in unfetched]}")

    no_pkce = [r for r in matrix if r["fetched"] and not r["PKCE_S256"]]
    print(f"- {len(no_pkce)} targets with NO PKCE-S256 advertised: {[r['target'] for r in no_pkce]}")

    pkce_plain = [r for r in matrix if r["PKCE_plain"]]
    print(f"- {len(pkce_plain)} targets accepting PKCE plain (SECURITY CONCERN): {[r['target'] for r in pkce_plain]}")

    no_pkj = [r for r in matrix if r["fetched"] and not r["private_key_jwt"]]
    print(f"- {len(no_pkj)} targets NOT supporting private_key_jwt (weaker client-cred posture): {[r['target'] for r in no_pkj]}")

    v1_only = [r for r in matrix if r["fetched"] and r["smart_v1"] and not r["smart_v2"]]
    print(f"- {len(v1_only)} targets on SMART v1 only (no v2 permission model): {[r['target'] for r in v1_only]}")

    print(f"\nResults saved: {out_dir}/matrix.json")


if __name__ == "__main__":
    asyncio.run(main())
