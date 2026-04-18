"""Deep server fingerprinting.

Identifies the underlying stack, versions, and pre-production code by probing:
- /version endpoints (git commit, build timestamp)
- Capability statement software version + status
- Common framework endpoints (actuator, swagger, api-docs)
- Response header fingerprints (Server, X-Powered-By, framework hints)
- Error page fingerprints (IdentityServer4, HAPI FHIR, Spring Boot, Rails Devise)

Findings from CMS testing:
- BB2: "Blue Button API: Direct 2.242.0" version disclosed
- DPC: git commit + timestamp on /api/v1/version
- DPC: "0.4.0-SNAPSHOT" Maven dev build from 2019 in production
- BCDA: /_version returns "r285", /_health exposes "ssas" dependency
- AB2D: /v3/api-docs fully exposes OpenAPI 3.1 spec
- AB2D: Spring Boot Actuator at /actuator (auth-required)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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


@dataclass
class FingerprintReport:
    base_url: str
    server_header: str = ""
    x_powered_by: str = ""
    frameworks_detected: list[str] = field(default_factory=list)
    version_endpoints: dict[str, str] = field(default_factory=dict)
    swagger_urls: list[str] = field(default_factory=list)
    actuator_urls: list[str] = field(default_factory=list)
    git_commits: list[str] = field(default_factory=list)
    build_timestamps: list[str] = field(default_factory=list)
    software_name: str = ""
    software_version: str = ""
    is_snapshot_build: bool = False
    capability_status: str = ""
    capability_date: str = ""


# Known framework fingerprints in response bodies
FRAMEWORK_FINGERPRINTS = {
    "HAPI FHIR": ["hapi-fhir", "ca.uhn.fhir", "formatCommentsPre"],
    "IdentityServer4": ["IdentityServer4", "/lib/bootstrap/dist/css/bootstrap.min.css", "cfdj8"],
    "IdentityServer (Duende)": ["Duende.IdentityServer"],
    "Spring Boot": ["spring-boot", "whitelabel", "/actuator"],
    "Spring Security": ["spring.security", "SpringSecurity"],
    "Django OAuth Toolkit": ["django-oauth-toolkit", "oauth2_provider", "django.contrib.admin"],
    "Django REST Framework": ["DRF Browsable API", "You do not have permission to perform"],
    "Dropwizard": ["dropwizard", "io.dropwizard"],
    "Rails Devise": ["devise", "rails-ujs", "csrf-param"],
    "ASP.NET Core": ["ASP.NET", "Microsoft.AspNetCore"],
    "Jetty": ["Powered by Jetty://", "jetty"],
    "Tomcat": ["Apache Tomcat", "tomcat-embed"],
    "New Relic Browser": ["NREUM", "nr-data.net"],
}


VERSION_ENDPOINTS = [
    "/version",
    "/api/v1/version",
    "/api/v2/version",
    "/api/version",
    "/_version",
    "/build-info",
    "/info",
    "/api/v1/info",
    "/actuator/info",
    "/health",
    "/_health",
    "/api/v1/health",
    "/api/v1/metadata",
]

SWAGGER_ENDPOINTS = [
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger",
    "/api/v1/api-docs",
    "/api/v1/swagger-ui/",
]

ACTUATOR_ENDPOINTS = [
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/actuator/heapdump",
    "/actuator/prometheus",
]


def detect_frameworks(text: str) -> list[str]:
    """Scan response text for framework fingerprints."""
    found = []
    for framework, patterns in FRAMEWORK_FINGERPRINTS.items():
        if any(p in text for p in patterns):
            found.append(framework)
    return found


def extract_git_commit(text: str) -> str | None:
    """Extract a likely git commit hash from a response."""
    # Short (7-8 char) or full (40 char) git commit hashes
    match = re.search(r'\b([0-9a-f]{7,8})\b(?:[^0-9a-f]|$)', text)
    if match:
        return match.group(1)
    return None


def extract_timestamp(text: str) -> str | None:
    """Extract an ISO 8601 timestamp from a response."""
    match = re.search(
        r'\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b', text
    )
    if match:
        return match.group(1)
    return None


async def probe_version_endpoints(
    client: FHIRClient, report: FingerprintReport
) -> None:
    """Probe known version/info endpoints."""
    for path in VERSION_ENDPOINTS:
        url = f"{report.base_url.rstrip('/')}{path}"
        # Try multiple Accept types because some endpoints return text/plain,
        # others JSON, others FHIR
        for accept in ("*/*", "application/json", "application/fhir+json"):
            try:
                r = await client.get(url, headers={"Accept": accept})
                if r.status_code == 200 and r.text:
                    snippet = r.text[:300]
                    report.version_endpoints[path] = snippet

                    # Extract git commit
                    commit = extract_git_commit(snippet)
                    if commit:
                        report.git_commits.append(f"{path}: {commit}")

                    # Extract timestamp
                    ts = extract_timestamp(snippet)
                    if ts:
                        report.build_timestamps.append(f"{path}: {ts}")

                    # Detect frameworks
                    frameworks = detect_frameworks(r.text)
                    for fw in frameworks:
                        if fw not in report.frameworks_detected:
                            report.frameworks_detected.append(fw)
                    break  # Got a good response, move to next path
            except httpx.HTTPError:
                continue


async def probe_swagger_endpoints(
    client: FHIRClient, report: FingerprintReport
) -> None:
    """Probe known OpenAPI/Swagger endpoints."""
    for path in SWAGGER_ENDPOINTS:
        url = f"{report.base_url.rstrip('/')}{path}"
        try:
            r = await client.get(url, headers={"Accept": "*/*"})
            if r.status_code == 200:
                if "openapi" in r.text.lower() or "swagger" in r.text.lower():
                    report.swagger_urls.append(path)
        except httpx.HTTPError:
            pass


async def probe_actuator(client: FHIRClient, report: FingerprintReport) -> None:
    """Probe Spring Boot actuator endpoints."""
    for path in ACTUATOR_ENDPOINTS:
        url = f"{report.base_url.rstrip('/')}{path}"
        try:
            r = await client.get(url, headers={"Accept": "*/*"})
            if r.status_code != 404:
                report.actuator_urls.append(f"{path}:{r.status_code}")
                if r.status_code == 200:
                    frameworks = detect_frameworks(r.text)
                    for fw in frameworks:
                        if fw not in report.frameworks_detected:
                            report.frameworks_detected.append(fw)
        except httpx.HTTPError:
            pass


async def probe_base_headers(
    client: FHIRClient, report: FingerprintReport
) -> None:
    """Capture server response headers for fingerprinting."""
    try:
        r = await client.get(report.base_url, headers={"Accept": "*/*"})
        report.server_header = r.headers.get("server", "")
        report.x_powered_by = r.headers.get("x-powered-by", "")

        frameworks = detect_frameworks(r.text)
        for fw in frameworks:
            if fw not in report.frameworks_detected:
                report.frameworks_detected.append(fw)
    except httpx.HTTPError:
        pass


def analyze_fingerprint(
    report: FingerprintReport,
    capability: EndpointInfo | None,
    result: ScanResult,
) -> None:
    """Build findings from the fingerprint report."""
    # Pull software info from the capability statement if we have one
    if capability:
        report.software_name = capability.software_name
        report.software_version = capability.software_version

        if capability.raw_capability:
            report.capability_status = capability.raw_capability.get("status", "")
            report.capability_date = capability.raw_capability.get("date", "")

    # Check for SNAPSHOT / dev build indicators
    if any(
        m in report.software_version.upper() for m in ("SNAPSHOT", "DEV", "LOCAL", "DIRTY")
    ):
        report.is_snapshot_build = True
        result.add_finding(Finding(
            title=f"Production running Maven/dev snapshot build: {report.software_version}",
            severity=Severity.LOW,
            category=FindingCategory.CONFIG,
            description=(
                f"The server identifies as a development build: "
                f"{report.software_name} {report.software_version}. "
                f"`-SNAPSHOT` indicates an unreleased Maven dev build that should "
                f"not appear in production-adjacent environments. Suggests the "
                f"codebase has not undergone production hardening."
            ),
            endpoint=report.base_url,
            evidence={
                "software_name": report.software_name,
                "software_version": report.software_version,
                "capability_status": report.capability_status,
                "capability_date": report.capability_date,
            },
        ))

    # Draft status on production capability statement
    if report.capability_status == "draft":
        result.add_finding(Finding(
            title=f"Capability statement status is 'draft' (date: {report.capability_date})",
            severity=Severity.LOW,
            category=FindingCategory.CONFIG,
            description=(
                f"The FHIR capability statement at /metadata is marked status=draft "
                f"with date={report.capability_date}. Draft-status capability statements "
                f"indicate unstable API surfaces that should not be relied upon by clients."
            ),
            endpoint=report.base_url,
        ))

    # Git commit + timestamp disclosure
    if report.git_commits:
        result.add_finding(Finding(
            title=f"Git commit hash disclosed via {len(report.git_commits)} version endpoint(s)",
            severity=Severity.LOW,
            category=FindingCategory.INFO_DISC,
            description=(
                "One or more public endpoints disclose the exact git commit hash "
                "of the running build. Combined with the public source repository, "
                "this allows attackers to review all code changes up to that commit "
                "and identify recent security fixes not yet deployed."
            ),
            endpoint=report.base_url,
            evidence={
                "disclosures": report.git_commits,
                "build_timestamps": report.build_timestamps,
            },
        ))

    # Public OpenAPI spec
    if report.swagger_urls:
        result.add_finding(Finding(
            title=f"OpenAPI/Swagger specification publicly accessible at {len(report.swagger_urls)} path(s)",
            severity=Severity.INFO,
            category=FindingCategory.INFO_DISC,
            description=(
                "The API's OpenAPI specification is publicly accessible without "
                "authentication. This reveals all endpoints, parameters, schemas, "
                "and operation metadata — a recon goldmine for attackers."
            ),
            endpoint=report.base_url,
            evidence={"swagger_urls": report.swagger_urls},
        ))

    # Spring Boot Actuator detected — BUT we need corroborating evidence.
    # Many non-Spring apps have catch-all auth middleware that returns 401 for
    # any unknown path, producing false positives for "actuator present".
    # Only flag if:
    #  (a) at least one actuator endpoint returned 200 (truly open), OR
    #  (b) Spring framework is independently detected (via headers or response
    #      body fingerprints)
    if report.actuator_urls:
        open_actuators = [u for u in report.actuator_urls if u.endswith(":200")]
        has_spring_evidence = any(
            "Spring" in fw for fw in report.frameworks_detected
        )

        if open_actuators:
            result.add_finding(Finding(
                title=f"Spring Boot Actuator endpoints accessible ({len(open_actuators)} open)",
                severity=Severity.HIGH,
                category=FindingCategory.INFO_DISC,
                description=(
                    "Spring Boot Actuator endpoints are publicly accessible without "
                    "authentication. These can leak environment variables, heap dumps, "
                    "application mappings, and other internal state."
                ),
                endpoint=report.base_url,
                evidence={"open_endpoints": open_actuators},
            ))
        elif has_spring_evidence:
            # Auth-walled but Spring is independently detected — real actuator
            result.add_finding(Finding(
                title="Spring Boot Actuator present (auth-required)",
                severity=Severity.INFO,
                category=FindingCategory.INFO_DISC,
                description=(
                    "Spring Boot Actuator endpoints are present but require "
                    "authentication. Spring framework independently confirmed "
                    "via other signals."
                ),
                endpoint=report.base_url,
                evidence={
                    "actuator_paths": report.actuator_urls,
                    "framework_evidence": [
                        fw for fw in report.frameworks_detected if "Spring" in fw
                    ],
                },
            ))
        # else: silently ignore — likely a catch-all auth layer, not Actuator

    # Server header disclosure
    if report.server_header:
        result.add_finding(Finding(
            title=f"Server header discloses: {report.server_header}",
            severity=Severity.INFO,
            category=FindingCategory.INFO_DISC,
            description=(
                "The Server response header reveals the underlying web server / "
                "version. Consider stripping this header."
            ),
            endpoint=report.base_url,
            evidence={"server": report.server_header},
        ))


async def run_fingerprint_scan(
    client: FHIRClient,
    config: TargetConfig,
    result: ScanResult,
    capability: EndpointInfo | None = None,
) -> FingerprintReport:
    """Run the full fingerprinting scan."""
    console.print("\n[bold]Running deep fingerprint scan...[/]")

    report = FingerprintReport(base_url=config.base_url)

    await probe_base_headers(client, report)
    await probe_version_endpoints(client, report)
    await probe_swagger_endpoints(client, report)
    await probe_actuator(client, report)

    console.print(f"\n  Server header: {report.server_header or '(not set)'}")
    console.print(f"  X-Powered-By: {report.x_powered_by or '(not set)'}")
    console.print(f"  Frameworks detected: {report.frameworks_detected or 'none'}")
    console.print(f"  Version endpoints: {list(report.version_endpoints.keys())}")
    console.print(f"  Swagger URLs: {report.swagger_urls}")
    console.print(f"  Actuator URLs: {report.actuator_urls}")
    console.print(f"  Git commits leaked: {report.git_commits}")

    analyze_fingerprint(report, capability, result)

    return report
