"""SMART-on-FHIR discovery scanner.

Fetches `/.well-known/smart-configuration` (with fallback to openid-configuration)
from a FHIR base URL, parses the config, and normalizes capability flags / auth
methods / scope sets for cross-vendor comparison.

Per SMART App Launch IG v2, the config surfaces the server's PKCE posture,
supported grant types, permission model (v1 vs v2), and capability flags like
`launch-ehr`, `permission-offline`, `sso-openid-connect`. A cross-vendor survey
of these values is the simplest published-dataset form of healthcare SMART
posture research.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx


WELL_KNOWN_PATHS = [
    "/.well-known/smart-configuration",
    "/.well-known/openid-configuration",
    "/metadata",  # fallback: CapabilityStatement has SMART ext under rest.security
]

# SMART v2 capability flags we care about (SMART App Launch IG 2.2.0)
KNOWN_CAPABILITIES = {
    "launch-ehr",
    "launch-standalone",
    "authorize-post",
    "client-public",
    "client-confidential-symmetric",
    "client-confidential-asymmetric",
    "sso-openid-connect",
    "context-banner",
    "context-style",
    "context-ehr-patient",
    "context-ehr-encounter",
    "context-standalone-patient",
    "context-standalone-encounter",
    "permission-offline",
    "permission-online",
    "permission-patient",
    "permission-user",
    "permission-v1",
    "permission-v2",
}


@dataclass
class SmartConfigResult:
    target: str
    source_url: str
    http_status: int
    fetched: bool = False
    raw_config: dict | None = None

    # Normalized fields
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    revocation_endpoint: str = ""
    introspection_endpoint: str = ""
    registration_endpoint: str = ""
    jwks_uri: str = ""

    grant_types_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)

    # Derived posture flags
    supports_private_key_jwt: bool = False
    supports_pkce: bool = False
    accepts_pkce_plain: bool = False  # Security risk: should be S256 only
    supports_smart_v1: bool = False
    supports_smart_v2: bool = False
    supports_openid: bool = False
    supports_refresh_tokens: bool = False
    supports_client_credentials: bool = False
    supports_authorization_code: bool = False
    capability_flags_unknown: list[str] = field(default_factory=list)
    error_note: str = ""


def normalize(cfg: dict, result: SmartConfigResult) -> None:
    """Populate normalized + derived fields from the raw config."""
    def _get_list(key: str) -> list[str]:
        v = cfg.get(key, []) or []
        return [x for x in v if isinstance(x, str)]

    result.authorization_endpoint = cfg.get("authorization_endpoint", "") or ""
    result.token_endpoint = cfg.get("token_endpoint", "") or ""
    result.revocation_endpoint = cfg.get("revocation_endpoint", "") or ""
    result.introspection_endpoint = cfg.get("introspection_endpoint", "") or ""
    result.registration_endpoint = cfg.get("registration_endpoint", "") or ""
    result.jwks_uri = cfg.get("jwks_uri", "") or ""

    result.grant_types_supported = _get_list("grant_types_supported")
    result.response_types_supported = _get_list("response_types_supported")
    result.scopes_supported = _get_list("scopes_supported")
    result.token_endpoint_auth_methods_supported = _get_list(
        "token_endpoint_auth_methods_supported"
    )
    result.code_challenge_methods_supported = _get_list(
        "code_challenge_methods_supported"
    )
    result.capabilities = _get_list("capabilities")

    # Derived flags
    auth_methods = result.token_endpoint_auth_methods_supported
    result.supports_private_key_jwt = "private_key_jwt" in auth_methods

    pkce_methods = result.code_challenge_methods_supported
    result.supports_pkce = "S256" in pkce_methods
    result.accepts_pkce_plain = "plain" in pkce_methods

    caps = set(result.capabilities)
    result.supports_smart_v1 = "permission-v1" in caps
    result.supports_smart_v2 = "permission-v2" in caps
    result.supports_openid = "sso-openid-connect" in caps

    grants = result.grant_types_supported
    result.supports_refresh_tokens = "refresh_token" in grants
    result.supports_client_credentials = "client_credentials" in grants
    result.supports_authorization_code = "authorization_code" in grants

    result.capability_flags_unknown = [c for c in caps if c not in KNOWN_CAPABILITIES]


async def fetch_smart_config(
    fhir_base: str,
    timeout: float = 15.0,
    user_agent: str = "fhirbug/smart-scanner MSOBB",
) -> SmartConfigResult:
    """Try well-known paths in order; return the first one that yields JSON."""
    result = SmartConfigResult(target=fhir_base, source_url="", http_status=0)

    # Some servers (AB2D) reject `application/fhir+json` with 406; some parsers interpret
    # the combined Accept header differently. Try standard, then fallback to JSON-only.
    accept_variants = [
        "application/json, application/fhir+json",
        "application/json",
        "application/fhir+json",
    ]

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    ) as client:
        for path in WELL_KNOWN_PATHS:
            url = fhir_base.rstrip("/") + path
            for accept in accept_variants:
                try:
                    r = await client.get(url, headers={"Accept": accept})
                except httpx.ConnectError:
                    result.error_note = "DNS or connection refused"
                    return result
                except httpx.HTTPError as e:
                    result.error_note = f"http error: {type(e).__name__}"
                    continue

                result.source_url = url
                result.http_status = r.status_code
                if r.status_code == 406:
                    # Try next Accept variant against the same path
                    continue
                if r.status_code != 200:
                    break  # move to next well-known path
                # 200 OK — try to parse below
                break
            else:
                continue  # all Accept variants failed for this path

            if result.http_status != 200:
                continue

            ctype = r.headers.get("content-type", "")
            try:
                cfg = r.json()
            except Exception:
                try:
                    cfg = json.loads(r.text)
                except Exception:
                    result.error_note = f"non-JSON 200 at {path} (ctype={ctype})"
                    continue

            # For /metadata CapabilityStatement, extract SMART security extensions
            if path == "/metadata" and isinstance(cfg, dict) and cfg.get("resourceType") == "CapabilityStatement":
                cfg = extract_smart_from_capstmt(cfg)
                if not cfg:
                    result.error_note = "CapabilityStatement had no SMART security extensions"
                    continue

            result.raw_config = cfg
            result.fetched = True
            normalize(cfg, result)
            return result

    if not result.error_note:
        result.error_note = f"no well-known config found (last status: {result.http_status})"
    return result


def extract_smart_from_capstmt(capstmt: dict) -> dict | None:
    """Extract SMART OAuth URIs from a FHIR CapabilityStatement security extension.

    Per FHIR R4 §B.3.1.1 + SMART App Launch IG, OAuth endpoints are under:
        rest[].security.extension
            url = http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris
            extension[] = { url: 'authorize'|'token'|'revoke', valueUri: <endpoint> }
    """
    for rest in capstmt.get("rest", []) or []:
        sec = rest.get("security") or {}
        for ext in sec.get("extension", []) or []:
            if "oauth-uris" in ext.get("url", ""):
                inner = {}
                for sub in ext.get("extension", []) or []:
                    name = sub.get("url", "")
                    uri = sub.get("valueUri", "")
                    if name and uri:
                        # Map to SMART config field names
                        key_map = {
                            "authorize": "authorization_endpoint",
                            "token": "token_endpoint",
                            "revoke": "revocation_endpoint",
                            "introspect": "introspection_endpoint",
                            "register": "registration_endpoint",
                        }
                        mapped = key_map.get(name, name)
                        inner[mapped] = uri
                if inner:
                    return inner
    return None


async def survey_targets(
    targets: list[dict[str, str]],
    concurrency: int = 4,
) -> list[SmartConfigResult]:
    """Run the scanner across a list of targets with bounded concurrency.

    Each target is a dict like {"name": "Epic", "fhir_base": "https://..."}
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(target: dict[str, str]) -> SmartConfigResult:
        async with sem:
            result = await fetch_smart_config(target["fhir_base"])
            result.target = target["name"]
            await asyncio.sleep(0.2)  # polite spacing
            return result

    return await asyncio.gather(*[_one(t) for t in targets])


def to_matrix_row(r: SmartConfigResult) -> dict:
    """Flatten a result into a row for the cross-vendor matrix."""
    return {
        "target": r.target,
        "fetched": r.fetched,
        "http_status": r.http_status,
        "source": r.source_url.rsplit("/", 1)[-1] if r.source_url else "",
        "PKCE_S256": r.supports_pkce,
        "PKCE_plain": r.accepts_pkce_plain,
        "private_key_jwt": r.supports_private_key_jwt,
        "openid": r.supports_openid,
        "refresh": r.supports_refresh_tokens,
        "auth_code": r.supports_authorization_code,
        "client_creds": r.supports_client_credentials,
        "smart_v1": r.supports_smart_v1,
        "smart_v2": r.supports_smart_v2,
        "n_scopes": len(r.scopes_supported),
        "n_caps": len(r.capabilities),
        "unknown_caps": r.capability_flags_unknown,
        "error": r.error_note,
    }
