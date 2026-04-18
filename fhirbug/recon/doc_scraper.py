"""Automated credential + endpoint extraction from vendor documentation.

Scrapes API documentation pages looking for:
- UUID-format client IDs
- Hex/base64 credential secrets
- Sandbox base URLs
- Token / OAuth endpoint URLs
- Curl example commands that reveal auth flows
- Paired (client_id, secret) tuples

Patterns learned from CMS docs:
- AB2D: contract_id + base64(client_id:secret) pairs in docs
- BCDA: 6 ACO pairs with 80-char hex secrets inline
- BB2: sandbox/prod endpoint URLs listed
- DPC: JWT format + auth endpoint URLs in the authorization guide

Designed to be run against any healthcare API vendor's developer portal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

from fhirbug.core.models import Finding, FindingCategory, ScanResult, Severity

console = Console()


# Patterns for credential extraction
RE_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
# Hex secrets: 32+ hex chars (common lengths: 32, 40, 64, 80, 128)
RE_HEX_SECRET = re.compile(r"\b[0-9a-f]{32,256}\b", re.IGNORECASE)
# Base64 blobs (suspiciously long — likely tokens, secrets, macaroons, JWTs)
RE_B64_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{50,}")
# URLs — focus on API / token endpoints
RE_API_URL = re.compile(
    r"https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9%/_.~?=&+-]*)?"
)
# Curl commands are a great source of auth flow info
RE_CURL = re.compile(r"curl\s+[^`\n]{1,500}", re.IGNORECASE)
# JWT (three base64 segments joined by dots)
RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b"
)
# client_id: / client_secret: style labels
RE_LABELED_CRED = re.compile(
    r"(client[_ ]?id|client[_ ]?secret|client[_ ]?token|api[_ ]?key|sandbox[_ ]?key|bearer[_ ]?token)"
    r"[\s:]*[`\"']?([A-Za-z0-9._-]{10,200})[`\"']?",
    re.IGNORECASE,
)


@dataclass
class DocScrapeResult:
    """Results extracted from a documentation page."""
    url: str
    status_code: int = 0
    uuids: list[str] = field(default_factory=list)
    hex_secrets: list[str] = field(default_factory=list)
    base64_blobs: list[str] = field(default_factory=list)
    api_urls: list[str] = field(default_factory=list)
    curl_commands: list[str] = field(default_factory=list)
    jwts: list[str] = field(default_factory=list)
    labeled_creds: dict[str, list[str]] = field(default_factory=dict)
    paired_credentials: list[tuple[str, str]] = field(default_factory=list)
    token_endpoints: list[str] = field(default_factory=list)
    sandbox_base_urls: list[str] = field(default_factory=list)
    fhir_base_urls: list[str] = field(default_factory=list)


def _strip_html(text: str) -> str:
    """Lightly strip HTML tags and normalize whitespace for regex matching."""
    # Remove script/style blocks first (their contents confuse extraction)
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.I)
    # Replace tags with spaces
    text = re.sub(r"<[^>]+>", " ", text)
    # HTML entities (common ones)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#x27;", "'").replace("&nbsp;", " ")
    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)
    return text


def _categorize_url(url: str) -> str:
    """Classify an API URL by its purpose."""
    lower = url.lower()
    if any(t in lower for t in ("/token", "/oauth", "/connect/token", "/auth/token")):
        return "token"
    if "/authorize" in lower or "/oauth/authorize" in lower:
        return "authorize"
    if "/introspect" in lower:
        return "introspect"
    if "/revoke" in lower:
        return "revoke"
    if ".well-known" in lower:
        return "well-known"
    if "/fhir" in lower or "/r4" in lower or "/stu3" in lower or "/dstu2" in lower:
        return "fhir"
    if "/metadata" in lower:
        return "metadata"
    if "sandbox" in lower:
        return "sandbox"
    return "other"


def _pair_credentials(text: str, uuids: list[str], hex_secrets: list[str]) -> list[tuple[str, str]]:
    """Try to pair client IDs with their secrets based on proximity in the text."""
    pairs = []
    if not uuids or not hex_secrets:
        return pairs

    # Find positions of UUIDs and hex secrets
    uuid_positions = [(m.start(), m.group()) for m in RE_UUID.finditer(text)]
    hex_positions = [(m.start(), m.group()) for m in RE_HEX_SECRET.finditer(text)]

    # Deduplicate keeping first occurrence
    seen_uuids: set[str] = set()
    uniq_uuid_positions = []
    for pos, val in uuid_positions:
        if val not in seen_uuids:
            seen_uuids.add(val)
            uniq_uuid_positions.append((pos, val))

    seen_hex: set[str] = set()
    uniq_hex_positions = []
    for pos, val in hex_positions:
        if val not in seen_hex:
            seen_hex.add(val)
            uniq_hex_positions.append((pos, val))

    # Simple pairing: walk through both sequences in order
    if len(uniq_uuid_positions) == len(uniq_hex_positions):
        for (u_pos, u_val), (h_pos, h_val) in zip(uniq_uuid_positions, uniq_hex_positions):
            pairs.append((u_val, h_val))
    else:
        # Nearest-neighbor pairing: for each UUID find the nearest hex secret
        # whose position is after the UUID (secrets usually follow IDs in docs)
        for u_pos, u_val in uniq_uuid_positions:
            candidates = [
                (abs(h_pos - u_pos), h_val)
                for h_pos, h_val in uniq_hex_positions
                if h_pos > u_pos
            ]
            if candidates:
                _, h_val = min(candidates)
                pairs.append((u_val, h_val))

    return pairs


def parse_doc_content(url: str, raw_html: str) -> DocScrapeResult:
    """Extract credentials, URLs, and curl examples from a doc page."""
    result = DocScrapeResult(url=url, status_code=200)

    # Keep RAW text (for curl/JWT extraction) and a cleaned text
    cleaned = _strip_html(raw_html)

    # UUIDs (client IDs, public key IDs)
    result.uuids = sorted(set(RE_UUID.findall(cleaned)))

    # Hex secrets
    result.hex_secrets = sorted(set(RE_HEX_SECRET.findall(cleaned)))
    # Filter out UUID hex chars (since UUIDs are hex too)
    result.hex_secrets = [
        s for s in result.hex_secrets
        if not any(u.replace("-", "") in s for u in result.uuids)
        and len(s) > 32
    ]

    # JWTs
    result.jwts = list(set(RE_JWT.findall(raw_html)))[:5]  # cap

    # API URLs — prefer raw HTML so we get the exact URL
    all_urls = list(set(RE_API_URL.findall(raw_html)))
    # Filter out obvious noise (google-analytics, fonts, etc.)
    noise_hosts = (
        "fonts.googleapis.com", "fonts.gstatic.com", "www.w3.org",
        "www.google-analytics.com", "schema.org", "googletagmanager.com",
        "ajax.googleapis.com", "cdn.jsdelivr.net", "cloudflare.com",
        "cookielaw.org", "bootstrap", "jquery",
    )
    filtered_urls = [
        u for u in all_urls
        if not any(n in u for n in noise_hosts)
    ]
    result.api_urls = filtered_urls[:50]

    for u in filtered_urls:
        cat = _categorize_url(u)
        if cat == "token":
            if u not in result.token_endpoints:
                result.token_endpoints.append(u)
        elif cat == "fhir":
            if u not in result.fhir_base_urls:
                result.fhir_base_urls.append(u)
        elif cat == "sandbox":
            if u not in result.sandbox_base_urls:
                result.sandbox_base_urls.append(u)

    # Curl commands
    result.curl_commands = [
        m.strip() for m in RE_CURL.findall(raw_html)[:10]
    ]

    # Labeled credentials
    for m in RE_LABELED_CRED.finditer(cleaned):
        label = m.group(1).lower().replace(" ", "_")
        val = m.group(2)
        result.labeled_creds.setdefault(label, []).append(val)

    # Try to pair UUIDs with hex secrets
    result.paired_credentials = _pair_credentials(
        cleaned, result.uuids, result.hex_secrets
    )

    # Base64 blobs (potential tokens/macaroons/JWTs)
    b64_candidates = RE_B64_BLOB.findall(raw_html)
    # Filter out things that look like JWTs (we already captured those)
    # and things that are just hex (UUIDs/secrets re-captured)
    b64_filtered = [
        b for b in set(b64_candidates)
        if "." not in b  # not a JWT
        and not all(c in "0123456789abcdef-" for c in b.lower())
    ]
    result.base64_blobs = sorted(b64_filtered, key=len, reverse=True)[:10]

    return result


async def scrape_doc_urls(
    urls: list[str],
    user_agent: str = "Mozilla/5.0 (fhirbug recon)",
    timeout: float = 30.0,
) -> list[DocScrapeResult]:
    """Fetch a list of documentation URLs and extract what we can."""
    results = []
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    ) as client:
        for url in urls:
            console.print(f"[cyan]Fetching:[/] {url}")
            try:
                r = await client.get(url)
                if r.status_code != 200:
                    console.print(f"  [yellow]{r.status_code}[/]")
                    results.append(DocScrapeResult(url=url, status_code=r.status_code))
                    continue

                parsed = parse_doc_content(url, r.text)
                results.append(parsed)
            except httpx.HTTPError as e:
                console.print(f"  [red]Error:[/] {e}")
                results.append(DocScrapeResult(url=url, status_code=0))

    return results


def print_scrape_summary(results: list[DocScrapeResult]) -> None:
    """Print a rich table summary of what we found."""
    table = Table(title="Doc Scrape Summary")
    table.add_column("URL", style="cyan", max_width=50)
    table.add_column("UUIDs", justify="right")
    table.add_column("Secrets", justify="right")
    table.add_column("Pairs", justify="right")
    table.add_column("Token EPs", justify="right")
    table.add_column("FHIR URLs", justify="right")
    table.add_column("Curl", justify="right")

    for r in results:
        table.add_row(
            r.url[-50:] if len(r.url) > 50 else r.url,
            str(len(r.uuids)),
            str(len(r.hex_secrets)),
            str(len(r.paired_credentials)),
            str(len(r.token_endpoints)),
            str(len(r.fhir_base_urls)),
            str(len(r.curl_commands)),
        )
    console.print(table)

    # Print the best paired credentials for each result
    for r in results:
        if r.paired_credentials:
            console.print(f"\n[bold]Credential pairs from {r.url}:[/]")
            for cid, secret in r.paired_credentials[:10]:
                secret_trunc = secret[:12] + "..." + secret[-6:] if len(secret) > 24 else secret
                console.print(f"  {cid}  :  {secret_trunc}")
        if r.token_endpoints:
            console.print(f"\n[bold]Token endpoints from {r.url}:[/]")
            for ep in r.token_endpoints[:5]:
                console.print(f"  {ep}")
        if r.fhir_base_urls:
            console.print(f"\n[bold]FHIR base URLs from {r.url}:[/]")
            for u in r.fhir_base_urls[:5]:
                console.print(f"  {u}")
        if r.curl_commands:
            console.print(f"\n[bold]Curl examples from {r.url}:[/]")
            for cmd in r.curl_commands[:3]:
                console.print(f"  {cmd[:200]}")


async def run_doc_scrape(
    urls: list[str],
    result: ScanResult,
) -> list[DocScrapeResult]:
    """Scrape a list of documentation URLs and add a finding if credentials were found."""
    scrape_results = await scrape_doc_urls(urls)
    print_scrape_summary(scrape_results)

    # Aggregate findings
    all_pairs: list[tuple[str, str]] = []
    all_token_eps: set[str] = set()
    all_fhir_urls: set[str] = set()
    total_uuids = 0
    total_secrets = 0

    for r in scrape_results:
        all_pairs.extend(r.paired_credentials)
        all_token_eps.update(r.token_endpoints)
        all_fhir_urls.update(r.fhir_base_urls)
        total_uuids += len(r.uuids)
        total_secrets += len(r.hex_secrets)

    # If we found paired credentials in vendor docs, that's a finding itself —
    # the vendor is publishing sandbox credentials inline, which is expected
    # but worth noting as an attack surface.
    if all_pairs:
        result.add_finding(Finding(
            title=f"Vendor documentation exposes {len(all_pairs)} sandbox credential pair(s) inline",
            severity=Severity.INFO,
            category=FindingCategory.INFO_DISC,
            description=(
                f"Scraped {len(scrape_results)} documentation page(s) and extracted "
                f"{len(all_pairs)} likely credential pairs. Vendor sandbox credentials "
                f"are typically published intentionally to let developers start testing, "
                f"but confirm these are sandbox-only and not production."
            ),
            endpoint=urls[0] if urls else "",
            evidence={
                "pages_scraped": [r.url for r in scrape_results],
                "credential_pairs": [
                    {"client_id": cid, "secret_prefix": s[:10] + "..."}
                    for cid, s in all_pairs[:20]
                ],
                "token_endpoints": sorted(all_token_eps),
                "fhir_urls": sorted(all_fhir_urls)[:20],
            },
        ))

    return scrape_results
