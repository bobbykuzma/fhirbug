"""Active probes against SMART-on-FHIR authorize endpoints.

Phase B follow-up to the discovery survey. For each target with a resolvable
`authorization_endpoint`, this runner fires 6 probe variants and captures the
response (status, redirect Location, error body). The cross-variant diff
reveals whether the server *enforces* what it *advertises* in the SMART
config for PKCE / state / scope.

Probe variants:
  1. baseline:       plausible valid-shaped request (fake client_id, PKCE S256, random state)
  2. no-pkce:        drops code_challenge + code_challenge_method entirely
  3. pkce-plain:     code_challenge_method=plain, bare challenge value
  4. no-state:       drops state parameter
  5. empty-state:    state=""
  6. scope-escalate: scope=system/*.* (aggressive escalation probe)

Safety:
  - ≤ 6 probes per target
  - 1s spacing minimum between probes on same target
  - Halt on 429 / 403 WAF-shaped response
  - All client_ids are obviously fake + research-marked
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sys
import urllib.parse
from pathlib import Path

import httpx

# Add the repo root to sys.path so `from fhirbug..` works when running
# this example directly from the repo without `pip install -e .`
sys.path.insert(0, str(Path(__file__).parent.parent))

# REQUIRED: Customize these with your own research contact info before running.
# User-Agent should clearly identify the research + contact email per most BBP scopes.
RESEARCHER_CONTACT = "researcher@example.com"  # ← SET THIS to your contact
USER_AGENT = f"fhirbug/smart-authorize-probe research {RESEARCHER_CONTACT}"

# Obviously-fake client_id + redirect_uri, no collision with real registered clients.
# `invalid` TLD is reserved (RFC 2606); DNS will never resolve it.
FAKE_CLIENT_ID = "fhirbug-research-probe-smart-authorize"
FAKE_REDIRECT = "https://fhirbug.research.invalid/callback"


def gen_pkce_s256() -> tuple[str, str]:
    """Generate a valid PKCE S256 (verifier, challenge) pair."""
    verifier = secrets.token_urlsafe(48)
    challenge_bytes = hashlib.sha256(verifier.encode()).digest()
    challenge = (
        __import__("base64").urlsafe_b64encode(challenge_bytes)
        .rstrip(b"=").decode()
    )
    return verifier, challenge


def build_probe(variant: str, authorize_endpoint: str) -> str:
    """Build an authorize-endpoint URL for a given probe variant."""
    state = secrets.token_urlsafe(16)
    pkce_verifier, pkce_challenge = gen_pkce_s256()

    # Baseline params (OAuth 2.0 / SMART v2 minimal)
    base = {
        "response_type": "code",
        "client_id": FAKE_CLIENT_ID,
        "redirect_uri": FAKE_REDIRECT,
        "scope": "openid patient/Patient.read",
        "state": state,
        "aud": authorize_endpoint.rsplit("/oauth2/", 1)[0] if "/oauth2/" in authorize_endpoint else "",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    }

    if variant == "baseline":
        params = dict(base)
    elif variant == "no-pkce":
        params = {k: v for k, v in base.items() if k not in ("code_challenge", "code_challenge_method")}
    elif variant == "pkce-plain":
        params = dict(base)
        params["code_challenge_method"] = "plain"
        params["code_challenge"] = pkce_verifier  # plain = verifier itself
    elif variant == "no-state":
        params = {k: v for k, v in base.items() if k != "state"}
    elif variant == "empty-state":
        params = dict(base)
        params["state"] = ""
    elif variant == "scope-escalate":
        params = dict(base)
        params["scope"] = "system/*.* user/*.* patient/*.*"
    else:
        raise ValueError(f"Unknown variant: {variant}")

    # Drop empty aud
    params = {k: v for k, v in params.items() if v != ""}
    query = urllib.parse.urlencode(params)
    separator = "&" if "?" in authorize_endpoint else "?"
    return authorize_endpoint + separator + query


async def probe_target(
    client: httpx.AsyncClient,
    target_name: str,
    authorize_endpoint: str,
    halt_flag: dict) -> list[dict]:
    """Run the 6 probe variants against one target. Returns a list of probe records."""
    variants = ["baseline", "no-pkce", "pkce-plain", "no-state", "empty-state", "scope-escalate"]
    results = []

    for variant in variants:
        if halt_flag["halt"]:
            results.append({"variant": variant, "skipped": "halted"})
            continue

        url = build_probe(variant, authorize_endpoint)
        try:
            # follow_redirects=False so we capture redirect Location header explicitly
            r = await client.get(url, follow_redirects=False, timeout=15.0)
        except httpx.HTTPError as e:
            results.append({
                "variant": variant,
                "error": f"{type(e).__name__}: {str(e)[:150]}",
            })
            await asyncio.sleep(1.2)
            continue

        # Halt on WAF / rate-limit signatures
        if r.status_code in (429) or (r.status_code == 403 and "AkamaiGHost" in r.headers.get("server", "")):
            halt_flag["halt"] = True

        # Capture key response fields
        location = r.headers.get("location", "")
        # Parse any error= / error_description= from the redirect URL
        redirect_err = ""
        redirect_err_desc = ""
        if location:
            try:
                parsed = urllib.parse.urlparse(location)
                qs = urllib.parse.parse_qs(parsed.query)
                redirect_err = qs.get("error", [""])[0]
                redirect_err_desc = qs.get("error_description", [""])[0]
            except Exception:
                pass

        results.append({
            "variant": variant,
            "status_code": r.status_code,
            "content_type": r.headers.get("content-type", ""),
            "server": r.headers.get("server", ""),
            "location": location[:200],
            "redirect_error": redirect_err,
            "redirect_error_description": redirect_err_desc[:200],
            "body_snippet": r.text[:300],
            "request_url": url[:250],
        })

        await asyncio.sleep(1.2)  # polite spacing

    return results


async def main() -> None:
    # Load the survey matrix + raw configs
    survey_dir = Path(__file__).parent / "jwt_fuzz_evidence" / "smart_survey"
    matrix = json.loads((survey_dir / "matrix.json").read_text())

    # Build targets list, only those with a reachable authorize_endpoint
    targets = []
    for row in matrix:
        if not row["fetched"]:
            continue
        # Load the per-target raw config to get authorize_endpoint
        safe = row["target"].replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
        cfg_path = survey_dir / f"{safe}_config.json"
        if not cfg_path.exists():
            continue
        cfg = json.loads(cfg_path.read_text())
        raw = cfg.get("raw_config") or {}
        auth_ep = raw.get("authorization_endpoint") if isinstance(raw, dict) else None
        if not auth_ep:
            continue
        targets.append({"name": row["target"], "authorize_endpoint": auth_ep})

    print(f"Probing {len(targets)} targets with 6 variants each (max {len(targets) * 6} requests)")

    out_dir = Path(__file__).parent / "jwt_fuzz_evidence" / "smart_authorize_probes"
    out_dir.mkdir(parents=True, exist_ok=True)

    halt_flag = {"halt": False}
    all_results = {}

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}) as client:
        for target in targets:
            print(f"\n=== {target['name']} ===")
            print(f"  authorize: {target['authorize_endpoint']}")
            if halt_flag["halt"]:
                print("  [SKIPPED, prior WAF halt]")
                continue
            results = await probe_target(client, target["name"], target["authorize_endpoint"], halt_flag)
            all_results[target["name"]] = {
                "authorize_endpoint": target["authorize_endpoint"],
                "probes": results,
            }
            # Summary per target
            for p in results:
                if "error" in p:
                    print(f"  {p['variant']:<16} ERROR: {p['error'][:80]}")
                elif "skipped" in p:
                    print(f"  {p['variant']:<16} SKIPPED")
                else:
                    err = p.get("redirect_error") or "(no redirect err)"
                    print(f"  {p['variant']:<16} [{p['status_code']}]  err={err!r}")

    (out_dir / "probe_results.json").write_text(json.dumps(all_results, indent=2, default=str))
    print(f"\nResults saved: {out_dir}/probe_results.json")
    print(f"Halted early: {halt_flag['halt']}")


if __name__ == "__main__":
    asyncio.run(main())
