"""CLI entry point — subcommands for recon, auth, fuzz, and full scan."""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console

from fhirbug import __version__
from fhirbug.core.client import FHIRClient
from fhirbug.core.config import TargetConfig
from fhirbug.core.models import ScanResult
from fhirbug.report.generator import print_summary, save_html, save_json

console = Console()

BANNER = r"""
  _____ _   _ ___ ____  _
 |  ___| | | |_ _|  _ \| |__  _   _  __ _
 | |_  | |_| || || |_) | '_ \| | | |/ _` |
 |  _| |  _  || ||  _ <| |_) | |_| | (_| |
 |_|   |_| |_|___|_| \_\_.__/ \__,_|\__, |
                                    |___/
  FHIRbug — Offensive FHIR Security Toolkit v{version}
""".format(version=__version__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fhirbug",
        description="FHIR endpoint recon and security testing toolkit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Global options
    parser.add_argument("--target", "-t", required=True, help="FHIR base URL (e.g. https://fhir.example.com/R4)")
    parser.add_argument("--token", help="Bearer token for authenticated requests")
    parser.add_argument("--client-id", help="OAuth client ID")
    parser.add_argument("--client-secret", help="OAuth client secret")
    parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Seconds between requests (default: 0.1)")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--proxy", help="HTTP proxy URL")
    parser.add_argument("--output-json", "-oj", help="Save JSON report to file")
    parser.add_argument("--output-html", "-oh", help="Save HTML report to file")

    sub = parser.add_subparsers(dest="command", help="Scan mode")

    # recon
    recon = sub.add_parser("recon", help="Reconnaissance only — enumerate capabilities and SMART config")

    # fingerprint
    fingerprint = sub.add_parser("fingerprint", help="Deep server fingerprinting — versions, frameworks, leaked info")

    # auth
    auth = sub.add_parser("auth", help="Authentication and authorization testing")
    auth.add_argument("--test-scopes", action="store_true", help="Test scope enforcement")
    auth.add_argument("--test-patient-boundary", help="Patient ID for context boundary testing")

    # cors
    cors = sub.add_parser("cors", help="CORS misconfiguration testing + PoC generator")
    cors.add_argument("--urls", nargs="+", help="Specific URLs to test (default: use metadata + a resource)")

    # client-enum
    client_enum = sub.add_parser("client-enum", help="OAuth client ID enumeration detection")
    client_enum.add_argument("--token-url", help="Token endpoint URL")
    client_enum.add_argument("--authorize-url", help="Authorization endpoint URL")
    client_enum.add_argument("--valid-client-id", required=True, help="A known valid client_id for the target")

    # jwt-fuzz
    jwt_fuzz = sub.add_parser("jwt-fuzz", help="JWT algorithm + claim fuzzing against a token endpoint")
    jwt_fuzz.add_argument("--token-url", required=True, help="Token endpoint URL to test")
    jwt_fuzz.add_argument("--private-key", help="Path to RSA/EC private key PEM for signing")
    jwt_fuzz.add_argument("--valid-kid", default="", help="Known valid public key id (kid)")
    jwt_fuzz.add_argument("--audience", default="", help="JWT aud claim value")
    jwt_fuzz.add_argument("--issuer", default="", help="JWT iss claim value")

    # serialization
    serialization = sub.add_parser("serialization", help="Response serialization bug detection (HAPI leak, amplification)")
    serialization.add_argument("--endpoints", nargs="+", help="Endpoints to probe")

    # enumeration
    enumeration = sub.add_parser("enumeration", help="Resource ID enumeration oracle (401 vs 404)")
    enumeration.add_argument("--endpoints", nargs="+", required=True, help="Endpoint templates containing {id}")
    enumeration.add_argument("--known-id", help="A known valid ID for baseline comparison")

    # bulk-export
    bulk_export = sub.add_parser("bulk-export", help="FHIR Bulk Data $export flow testing")
    bulk_export.add_argument("--group-id", help="Group ID to export")
    bulk_export.add_argument("--skip-typefilter", action="store_true", help="Skip _typeFilter fuzzing")
    bulk_export.add_argument("--skip-enumeration", action="store_true", help="Skip cross-tenant job enumeration")

    # doc-scrape
    doc_scrape = sub.add_parser("doc-scrape", help="Scrape vendor API docs for credentials, endpoints, curl examples")
    doc_scrape.add_argument("--urls", nargs="+", required=True, help="Documentation URLs to scrape")

    # error-oracle
    error_oracle = sub.add_parser("error-oracle", help="Map validation order via distinct error messages")
    error_oracle.add_argument("--token-url", required=True, help="Token endpoint URL to probe")
    error_oracle.add_argument("--valid-kid", default="", help="A known valid public key id (kid)")
    error_oracle.add_argument("--valid-client-id", default="", help="A known valid client_id / macaroon")

    # provenance
    provenance = sub.add_parser("provenance", help="JSON-in-header fuzzer (X-Provenance style)")
    provenance.add_argument("--target-url", required=True, help="Endpoint that accepts the header")
    provenance.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    provenance.add_argument("--header-name", default="X-Provenance", help="Header to fuzz")
    provenance.add_argument("--valid-org-id", default="", help="A valid organization UUID for baseline")
    provenance.add_argument("--valid-practitioner-id", default="", help="A valid practitioner UUID for baseline")
    provenance.add_argument("--other-org-id", default="00000000-0000-0000-0000-000000000000")
    provenance.add_argument("--other-practitioner-id", default="00000000-0000-0000-0000-000000000000")

    # fuzz
    fuzz = sub.add_parser("fuzz", help="Fuzzing — injection, includes, references")
    fuzz.add_argument("--skip-injection", action="store_true", help="Skip injection testing")
    fuzz.add_argument("--skip-includes", action="store_true", help="Skip _include/_revinclude testing")
    fuzz.add_argument("--skip-references", action="store_true", help="Skip reference traversal testing")

    # full
    full = sub.add_parser("full", help="Full scan — recon + fingerprint + auth + fuzz + serialization + cors")
    full.add_argument("--test-patient-boundary", help="Patient ID for context boundary testing")

    return parser


def build_config(args: argparse.Namespace) -> TargetConfig:
    return TargetConfig(
        base_url=args.target.rstrip("/"),
        access_token=args.token or "",
        client_id=args.client_id or "",
        client_secret=args.client_secret or "",
        timeout=args.timeout,
        max_concurrent=args.concurrency,
        rate_limit=args.rate_limit,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy or "",
    )


async def run_recon(client: FHIRClient, config: TargetConfig, result: ScanResult) -> None:
    from fhirbug.recon.capability import run_capability_recon
    from fhirbug.recon.endpoints import run_endpoint_discovery
    from fhirbug.recon.smart_config import run_smart_recon

    console.print("\n[bold blue]== PHASE 1: Reconnaissance ==[/]\n")

    info = await run_capability_recon(client, config, result)
    if info is None:
        console.print("[red]Recon failed — could not parse CapabilityStatement[/]")
        return
    result.endpoint_info = info

    await run_smart_recon(client, config, info, result)
    await run_endpoint_discovery(client, config, info, result)


async def run_auth(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    test_scopes: bool = False,
    patient_id: str = "",
) -> None:
    from fhirbug.auth.smart import test_registration_endpoint, test_token_endpoint
    from fhirbug.auth.tokens import analyze_token
    from fhirbug.auth.scopes import test_patient_context_boundary, test_scope_enforcement

    console.print("\n[bold blue]== PHASE 2: Authentication & Authorization ==[/]\n")

    info = result.endpoint_info
    if info is None:
        console.print("[yellow]No endpoint info — run recon first[/]")
        return

    # Token analysis
    token_scopes: list[str] = []
    token_patient: str = ""
    if config.access_token:
        console.print("[bold]Analyzing access token...[/]")
        analysis = analyze_token(config.access_token, result, config.base_url)
        scope_str = analysis.get("claims", {}).get("scope", "")
        if isinstance(scope_str, str):
            token_scopes = scope_str.split()
        token_patient = analysis.get("patient_context", "")

    # Token endpoint probing
    await test_token_endpoint(client, config, info, result)

    # Dynamic registration
    await test_registration_endpoint(client, config, info, result)

    # Scope enforcement
    if test_scopes and token_scopes:
        await test_scope_enforcement(client, config, info, result, token_scopes)

    # Patient context boundary
    pid = patient_id or token_patient
    if pid:
        await test_patient_context_boundary(client, config, info, result, pid)


async def run_fuzz(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    skip_injection: bool = False,
    skip_includes: bool = False,
    skip_references: bool = False,
) -> None:
    from fhirbug.fuzz.includes import (
        test_include_amplification,
        test_include_iterate,
        test_revinclude_amplification,
    )
    from fhirbug.fuzz.injection import (
        test_content_type_handling,
        test_header_injection,
        test_operation_injection,
    )
    from fhirbug.fuzz.references import (
        test_direct_resource_access,
        test_id_enumeration,
        test_version_access,
    )
    from fhirbug.fuzz.search import fuzz_search_abuse, fuzz_search_injection

    console.print("\n[bold blue]== PHASE 3: Fuzzing ==[/]\n")

    info = result.endpoint_info
    if info is None:
        console.print("[yellow]No endpoint info — run recon first[/]")
        return

    if not skip_injection:
        await fuzz_search_injection(client, config, info, result)
        await fuzz_search_abuse(client, config, info, result)
        await test_content_type_handling(client, config, info, result)
        await test_header_injection(client, config, info, result)
        await test_operation_injection(client, config, info, result)

    if not skip_includes:
        await test_include_amplification(client, config, info, result)
        await test_revinclude_amplification(client, config, info, result)
        await test_include_iterate(client, config, info, result)

    if not skip_references:
        await test_direct_resource_access(client, config, info, result)
        await test_id_enumeration(client, config, info, result)
        await test_version_access(client, config, info, result)


async def run_fingerprint(client: FHIRClient, config: TargetConfig, result: ScanResult) -> None:
    from fhirbug.recon.fingerprint import run_fingerprint_scan

    console.print("\n[bold blue]== Fingerprinting ==[/]\n")
    await run_fingerprint_scan(client, config, result, capability=result.endpoint_info)


async def run_cors(
    client: FHIRClient, config: TargetConfig, result: ScanResult, urls: list[str] | None = None
) -> None:
    from fhirbug.auth.cors_tester import run_cors_scan

    console.print("\n[bold blue]== CORS Testing ==[/]\n")
    if not urls:
        info = result.endpoint_info
        urls = [f"{config.base_url}/metadata"]
        if info and info.supported_resources:
            urls.append(f"{config.base_url}/{info.supported_resources[0]}")
    await run_cors_scan(client, result, urls)


async def run_client_enum(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    token_url: str,
    authorize_url: str,
    valid_client_id: str,
) -> None:
    from fhirbug.auth.client_enum import run_client_enumeration_scan

    console.print("\n[bold blue]== OAuth Client Enumeration ==[/]\n")
    await run_client_enumeration_scan(
        client, config, result,
        token_url=token_url or None,
        authorize_url=authorize_url or None,
        valid_client_id=valid_client_id,
    )


async def run_jwt_fuzz(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    token_url: str,
    private_key_path: str,
    valid_kid: str,
    audience: str,
    issuer: str,
) -> None:
    from fhirbug.auth.jwt_fuzzer import run_full_jwt_fuzz
    from pathlib import Path

    console.print("\n[bold blue]== JWT Fuzzing ==[/]\n")

    pk_bytes = Path(private_key_path).read_bytes() if private_key_path else None

    async def submit(jwt: str):
        r = await client.post(
            token_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        # We need to include the JWT as client_assertion — using a form post
        import httpx
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "scope": "system/*.*",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": jwt,
                },
                headers={"Accept": "application/json"},
            )
            return resp.status_code, resp.text, dict(resp.headers)

    import time, uuid as uuid_mod
    now = int(time.time())
    default_header = {"alg": "RS384", "kid": valid_kid or "unknown"}
    default_payload = {
        "iss": issuer,
        "sub": issuer,
        "aud": audience or token_url,
        "exp": now + 300,
        "iat": now,
        "jti": str(uuid_mod.uuid4()),
    }

    await run_full_jwt_fuzz(
        target_url=token_url,
        submit_fn=submit,
        default_header=default_header,
        default_payload=default_payload,
        result=result,
        private_key_pem=pk_bytes,
        valid_kid=valid_kid,
    )


async def run_serialization(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    endpoints: list[str] | None = None,
) -> None:
    from fhirbug.fuzz.serialization import run_serialization_scan

    console.print("\n[bold blue]== Serialization Bug Scan ==[/]\n")
    if not endpoints:
        endpoints = [
            f"{config.base_url}/metadata",
            f"{config.base_url}/Patient",
        ]
    await run_serialization_scan(client, result, endpoints)


async def run_enumeration(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    endpoints: list[str],
    known_id: str | None = None,
) -> None:
    from fhirbug.fuzz.enumeration import run_enumeration_scan

    console.print("\n[bold blue]== ID Enumeration Oracle Scan ==[/]\n")
    await run_enumeration_scan(client, config, result, endpoints, known_id)


async def run_bulk_export(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    group_id: str | None = None,
    skip_typefilter: bool = False,
    skip_enumeration: bool = False,
) -> None:
    from fhirbug.fuzz.bulk_export import run_bulk_export_scan

    console.print("\n[bold blue]== Bulk Export Flow Scan ==[/]\n")
    await run_bulk_export_scan(
        client, config, result,
        group_id=group_id,
        fuzz_typefilter=not skip_typefilter,
        test_enumeration=not skip_enumeration,
    )


async def run_doc_scrape(
    config: TargetConfig,
    result: ScanResult,
    urls: list[str],
) -> None:
    from fhirbug.recon.doc_scraper import run_doc_scrape as scrape

    console.print("\n[bold blue]== Documentation Scrape ==[/]\n")
    await scrape(urls, result)


async def run_error_oracle(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    token_url: str,
    valid_kid: str,
    valid_client_id: str,
) -> None:
    from fhirbug.recon.error_oracles import run_error_oracle_scan

    console.print("\n[bold blue]== Error Oracle Mapping ==[/]\n")
    await run_error_oracle_scan(
        client, result,
        token_url=token_url,
        valid_kid=valid_kid,
        valid_client_id=valid_client_id,
    )


async def run_provenance(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    target_url: str,
    method: str,
    header_name: str,
    valid_org_id: str,
    valid_practitioner_id: str,
    other_org_id: str,
    other_practitioner_id: str,
) -> None:
    from fhirbug.fuzz.provenance import run_provenance_fuzz

    console.print("\n[bold blue]== JSON-in-Header Fuzz ==[/]\n")
    await run_provenance_fuzz(
        client, result,
        target_url=target_url,
        method=method,
        header_name=header_name,
        valid_org_id=valid_org_id,
        valid_practitioner_id=valid_practitioner_id,
        other_org_id=other_org_id,
        other_practitioner_id=other_practitioner_id,
    )


async def async_main(args: argparse.Namespace) -> None:
    config = build_config(args)
    result = ScanResult(target=config.base_url)

    async with FHIRClient(config) as client:
        command = args.command or "full"

        if command == "recon":
            await run_recon(client, config, result)

        elif command == "fingerprint":
            await run_recon(client, config, result)
            await run_fingerprint(client, config, result)

        elif command == "auth":
            await run_recon(client, config, result)
            await run_auth(
                client, config, result,
                test_scopes=getattr(args, "test_scopes", False),
                patient_id=getattr(args, "test_patient_boundary", "") or "",
            )

        elif command == "cors":
            await run_recon(client, config, result)
            await run_cors(client, config, result, urls=getattr(args, "urls", None))

        elif command == "client-enum":
            await run_client_enum(
                client, config, result,
                token_url=getattr(args, "token_url", "") or "",
                authorize_url=getattr(args, "authorize_url", "") or "",
                valid_client_id=args.valid_client_id,
            )

        elif command == "jwt-fuzz":
            await run_jwt_fuzz(
                client, config, result,
                token_url=args.token_url,
                private_key_path=getattr(args, "private_key", "") or "",
                valid_kid=getattr(args, "valid_kid", "") or "",
                audience=getattr(args, "audience", "") or "",
                issuer=getattr(args, "issuer", "") or "",
            )

        elif command == "serialization":
            await run_recon(client, config, result)
            await run_serialization(
                client, config, result,
                endpoints=getattr(args, "endpoints", None),
            )

        elif command == "enumeration":
            await run_enumeration(
                client, config, result,
                endpoints=args.endpoints,
                known_id=getattr(args, "known_id", None),
            )

        elif command == "bulk-export":
            await run_recon(client, config, result)
            await run_bulk_export(
                client, config, result,
                group_id=getattr(args, "group_id", None),
                skip_typefilter=getattr(args, "skip_typefilter", False),
                skip_enumeration=getattr(args, "skip_enumeration", False),
            )

        elif command == "doc-scrape":
            await run_doc_scrape(config, result, urls=args.urls)

        elif command == "error-oracle":
            await run_error_oracle(
                client, config, result,
                token_url=args.token_url,
                valid_kid=getattr(args, "valid_kid", "") or "",
                valid_client_id=getattr(args, "valid_client_id", "") or "",
            )

        elif command == "provenance":
            await run_provenance(
                client, config, result,
                target_url=args.target_url,
                method=args.method,
                header_name=args.header_name,
                valid_org_id=getattr(args, "valid_org_id", "") or "",
                valid_practitioner_id=getattr(args, "valid_practitioner_id", "") or "",
                other_org_id=args.other_org_id,
                other_practitioner_id=args.other_practitioner_id,
            )

        elif command == "fuzz":
            await run_recon(client, config, result)
            await run_fuzz(
                client, config, result,
                skip_injection=getattr(args, "skip_injection", False),
                skip_includes=getattr(args, "skip_includes", False),
                skip_references=getattr(args, "skip_references", False),
            )

        elif command == "full":
            await run_recon(client, config, result)
            await run_fingerprint(client, config, result)
            await run_auth(
                client, config, result,
                test_scopes=True,
                patient_id=getattr(args, "test_patient_boundary", "") or "",
            )
            await run_serialization(client, config, result)
            await run_cors(client, config, result)
            await run_fuzz(client, config, result)

    result.finalize()
    print_summary(result)

    console.print(f"\n[dim]Requests: {client.request_count} | Errors: {client.error_count}[/]")

    if args.output_json:
        save_json(result, args.output_json)
    if args.output_html:
        save_html(result, args.output_html)


def main() -> None:
    console.print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/]")
        sys.exit(130)
