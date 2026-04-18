# FHIR Bug-Hunting Playbook

A working methodology for security research against FHIR APIs. Distilled
from a focused engagement against the CMS FHIR programs (Blue Button 2.0,
AB2D, BCDA, DPC) and a cross-vendor OAuth survey.

This is an operator's playbook, not a textbook. Each section maps to a
FHIRbug toolkit command so you can move from reading to running in one
copy/paste.

---

## The 6-Phase Workflow

Every FHIR target gets the same six phases, in order. Each phase has an
exit criterion and a toolkit command.

### Phase 1. Reconnaissance (read-only)

Goal: understand what the target exposes before sending any attack
payloads. This phase should generate no alarms.

```bash
# FHIR capability + SMART config + endpoint enumeration
python3 -m fhirbug -t https://example.com/fhir recon

# Scrape vendor API docs for credentials + auth endpoints
python3 -m fhirbug -t https://example.com doc-scrape \
  --urls https://example.com/api/docs \
         https://example.com/api/docs/auth \
         https://example.com/developers
```

Capture:

- FHIR version (R4, STU3, DSTU2, R5)
- Vendor and software name plus version
- SMART-on-FHIR configuration (grant types, scopes, PKCE, dynamic registration)
- Supported resources and write operations
- Any `$everything`, `$export`, `$graphql` operations
- Token, authorize, introspection, revocation endpoint URLs
- Publicly documented sandbox credentials

Exit criterion: you have a map of the API surface and at minimum one set
of sandbox credentials (or documentation describing how to obtain them).

### Phase 2. Fingerprinting (read-only, deeper)

Goal: identify the exact technology stack. Vendors reuse frameworks, so
framework-specific bugs become reusable findings.

```bash
python3 -m fhirbug -t https://example.com/fhir fingerprint
```

Look for:

- Build version or git commit on `/version`, `/info`, `/actuator/info`
- Maven SNAPSHOT builds in production (`-SNAPSHOT` indicates a dev build leaked)
- Draft capability statements (a date from 2+ years ago indicates the API is unmaintained)
- Spring Boot Actuator (often auth-walled but worth probing)
- OpenAPI/Swagger specs publicly accessible at `/v3/api-docs`, `/swagger-ui/`
- Server headers and X-Powered-By version disclosure
- Framework error fingerprints in response bodies:
  - HAPI FHIR: `ca.uhn.fhir`, `formatCommentsPre`
  - Spring Boot: `whitelabel`, `/actuator`
  - Django OAuth Toolkit: `oauth2_provider`, `DRF Browsable`
  - IdentityServer4: `IdentityServer4`, `/lib/bootstrap`
  - Rails Devise: `devise`, `/admin/internal/sign_in`
  - Dropwizard: `io.dropwizard`

Real-world examples (all CWE-200, typically LOW on their own but huge force multipliers for everything downstream):

- **CMS DPC: `0.4.0-SNAPSHOT` from 2019 in a production-adjacent sandbox.** A SNAPSHOT build running in anything that touches live credentials or sandbox beneficiaries is a code-posture red flag. It also told us the codebase had been effectively frozen for years, which narrows the CVE search space dramatically. Reproduces in under 10 seconds with `fingerprint`.
- **CMS DPC: git commit `83a47fa` plus build timestamp exposed on `/api/v1/version`.** With the git SHA you can pull the exact source from the public CMSgov repo, diff against main, and read the fixes that haven't been deployed yet. That flipped DPC from blackbox to whitebox for the rest of the engagement.
- **CMS BCDA: `/_version` returns `r285` and `/_health` leaks `ssas` and `database` references.** The `ssas` string alone told us BCDA uses a custom Go SSAS auth server rather than the CMS-standard Okta. That one word redirected the entire attack plan for BCDA.
- **CMS BB2: `Blue Button API: Direct 2.242.0` in the CapabilityStatement `software.version` field.** FHIR R4 lets vendors expose version strings here; most do, and most should not at this level of precision.

### Phase 3. OAuth and Auth Attack Surface

Goal: find bugs in how the server handles authentication protocols before
touching any user data.

#### 3a. Client ID enumeration (MANDATORY on every target)

```bash
python3 -m fhirbug -t https://example.com client-enum \
  --token-url https://example.com/oauth/token \
  --authorize-url https://example.com/oauth/authorize \
  --valid-client-id <any_known_valid_client_id>
```

Field note: cross-stack testing of seven payer/platform OAuth servers
found five of seven vulnerable. Not a vendor-specific bug. It is systemic
across IBM Security Verify, Okta, Django OAuth Toolkit, and custom Node.js
wrappers. Only custom Go implementations and Auth0-style managed domains
got it right. Run this check on every target.

Pattern to catch: the token endpoint returns measurably different
responses for "valid client, wrong secret" vs. "invalid client." Per RFC
6749 §5.2, the `invalid_client` error code should be the same, but most
stacks leak via `error_description`. Test both the token endpoint and the
authorize endpoint. Humana leaked via authorize while timing out on token.

Real examples (both CWE-204, reproduce in under five minutes with `client-enum`):

- **CMS BB2 `/v2/o/token/`** (Django OAuth Toolkit default configuration):
  - Valid client, wrong secret → `401 {"error":"invalid_client"}`
  - Invalid client → `400 {"error":"invalid_client", "error_description":"Application does not exist (client_id)"}`
  - Two oracles in one response: the status code (401 vs 400) and the body (`error_description` present or absent). You don't even need to parse JSON to split the two cases apart. Upstream bug: Django OAuth Toolkit's default handler returns `OAuthLibError` with the application name for unknown clients.
  - Fix direction: replace the default with a handler that returns a uniform 400 plus no `error_description`, or at minimum the same status code for both failure modes.

- **CMS AB2D Okta tenant (`test.idp.idm.cms.gov`):**
  - Valid client: OAuth-spec JSON format (`{"error":"invalid_client"}`)
  - Invalid client: Okta-native JSON format (`{"errorCode":"invalid_client","errorSummary":"...","errorLink":"..."}`)
  - Same underlying bug as BB2, different vendor entirely. Okta's error envelope is shaped differently from the OAuth-spec envelope, and Okta only emits the native shape when the client_id isn't recognized. Byte-distinguishable without any status-code oracle.
  - Fix direction: Okta has a per-authorization-server "Uniform error response" toggle in the admin console. Flip it on. Also fixes the same bug in every other Okta tenant at the organization.

#### 3b. JWT fuzzing (if the target uses JWT client assertions)

```bash
python3 -m fhirbug -t https://example.com jwt-fuzz \
  --token-url https://example.com/oauth/token \
  --private-key path/to/key.pem \
  --valid-kid <kid_from_portal> \
  --audience https://example.com/oauth/token \
  --issuer <client_id_or_macaroon>
```

Attack classes:

| Attack | Why |
|--------|-----|
| `alg=none` | Server might accept unsigned tokens |
| `alg=HS256` with public key as secret | Key confusion: server HMACs with the same key it would verify |
| Wrong `alg` header vs actual signature algorithm | Algorithm lookup bypass |
| Missing `kid` | NPE-style crash reveals Java variable names |
| `kid` pointing to another tenant's key | Key confusion or enumeration |
| Missing `exp`, past `exp`, far-future `exp` | Expiration enforcement |
| `jti` replay | Replay protection |
| `iss != sub` | Claim consistency check |
| Claim confusion (`iss`, `sub`, `client_id` all differ) | Which one does the server use? |
| Signature stripping, wrong-key signing | Verification bypass |
| `alg` case variants (`None`, `NONE`) | Case-sensitive allowlist bypass |
| Header key injection (`jwk`, `jku`, `x5c`, `x5u`) | Header-provided key trust |
| SMART scope escalation in client_assertion | Scope broader than registered |

Real examples (all CMS DPC `/Token/auth`, reproduce in about 10 minutes with `jwt-fuzz`):

- **Missing `kid` header returns `500 "Cannot invoke String.length() because name is null"`.** CWE-476 null pointer dereference plus CWE-209 information exposure through error message. The Java variable holding the kid is named `name`, and `.length()` is called before a null check. Every JWT attack path that legitimately omits `kid` (header-embedded-jwk probes, x5c-embedded probes, x5u SSRF probes, wrong-key signing without kid) trips the same crash. Severity climbs with the systematic nature: it's not one missing null check, it's a gap that's reachable from many attack directions. Fix: wrap the kid lookup in a defensive null guard and return a uniform 400.
- **Invalid JWT structure returns `500 "Cannot deserialize Macaroon"`.** CWE-755 improper handling of exceptional conditions. DPC's macaroon deserializer is reachable before JWS validation completes, so garbage JWTs hit the macaroon path and throw. Useful to an attacker mostly as a DoS amplifier (unauthenticated 500-generator) but also useful as a fingerprint for reachability-order analysis.
- **`client_id` claim is ignored; the server actually checks `iss == sub`.** CWE-209 misleading error message. The server rejects JWTs with `"JWT must have client_id"`, but a JWT with the right iss/sub and a deliberately-wrong `client_id` value authenticates successfully. The documentation says one thing, the error message says a second thing, and the implementation does a third. An attacker reading the error message would spend hours constructing JWTs with valid `client_id` claims; the real shape is `iss == sub == client_token` and `client_id` is dead code. Not a vuln on its own, but a rich seed for the next attacker who probes deeper.

#### 3c. Error oracle mapping

```bash
python3 -m fhirbug -t https://example.com error-oracle \
  --token-url https://example.com/oauth/token \
  --valid-kid <kid> \
  --valid-client-id <client_id>
```

What this detects: distinct error messages per validation step. Five or
more distinct errors indicates a validation-order leak. It also catches
unhandled 500 exceptions and framework fingerprints inside error text.

Real example (CWE-209, reproduces in 2 minutes with `error-oracle`): CMS
DPC `/Token/auth` exposes at least eight distinct error messages, each
tied to a specific validation step. "Invalid JWT" ≠ "JWT must have
client_id" ≠ "JWT header must have kid value" ≠ "Cannot find public key
with id: X" ≠ "Cannot deserialize Macaroon." An attacker maps the whole
validation chain in a single probe burst, then crafts inputs that satisfy
the early checks and fail the late ones, reaching code paths the early
rejects would have hidden. Exactly how we found the
macaroon-deserialization 500. Fix: return one `invalid_request` error for
every JWT validation failure, log specifics server-side only.

### Phase 4. CORS and Response Bugs

Goal: find browser-originated attack paths and response-handling bugs.

```bash
# CORS probing (generates a working HTML PoC on finding)
python3 -m fhirbug -t https://example.com/fhir cors

# Serialization / amplification detection
python3 -m fhirbug -t https://example.com/fhir serialization \
  --endpoints https://example.com/fhir/metadata \
              https://example.com/fhir/Patient
```

CORS to catch. The headline bug: `ACAO: *` plus `Authorization` header in
`ACAH`. This combo lets any JavaScript on any origin read PHI when it has
a token. The CORS spec blocks wildcard plus credentials (cookies), but
Bearer tokens in the `Authorization` header are not subject to that
restriction.

Real example (CMS BB2, CWE-942 Permissive Cross-domain Policy, reproduces
instantly with `cors` and ~1 minute with the auto-generated PoC HTML):

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: accept, authorization, content-type, user-agent, ...
```

A cross-origin `fetch()` from `evil.example.com` with a stolen Bearer
token returns patient demographics. The `cors` module drops an HTML PoC
into `findings/` that embeds the target URL and a paste-your-token input;
open the HTML from a different origin (file:// is fine), paste a valid
token, and the exfil fires. Severity: HIGH conditional on token leakage
happening elsewhere (XSS elsewhere on the token-holder's environment,
mobile app with a WebView, malicious browser extension). The CORS gap
turns every unrelated token leak into a cross-origin PHI exfil. Fix:
remove the wildcard. List registered partner-app origins explicitly, and
don't include `authorization` in `Access-Control-Allow-Headers` unless
each listed origin genuinely needs to send authenticated requests.

Serialization bugs to catch:

- **HAPI FHIR internal fields (`formatCommentsPre`, `formatCommentsPost`) leaking in error responses.** CWE-200 plus CWE-405 when amplification is present. Often indicates a custom serializer bypassing HAPI's own parser path rather than bypassing `@JsonIgnore` annotations. Those fields are unannotated in HAPI's source model; HAPI's own `JsonParser` programmatically suppresses them on R4+ via `isSupportsFhirComment() == false`. Their presence means the service routed the OperationOutcome through a generic `ObjectMapper` rather than through `FhirContext.newJsonParser()`. Reproduces in 30 seconds with `serialization`. Real instance on CMS DPC: 168 KB response body for a 0-byte POST to `/api/v1/Token/validate`.
- **Empty-body response amplification.** CWE-405. A tiny request returns a massive response. On CMS DPC the `_ratio` was effectively infinite (0-byte input, 168 KB output). Worth flagging even when the content itself isn't sensitive, because it turns an unauthenticated endpoint into a bandwidth-amplification primitive. Fix: cap response size on error paths, or reject empty POST bodies with a small 400 at the edge.
- **Stack trace or framework internal leakage in error bodies.** CWE-209. Java/Python traceback lines, internal class names, partial query text. Low on its own, high when it reveals the exact line of code to attack next.

### Phase 5. Data Layer Attacks (authenticated)

Goal: now that you have a token, attack the data layer.

Prerequisites:

- Completed OAuth flow with a synthetic beneficiary account
- Bearer token saved

```bash
# IDOR / search injection / include abuse / version history
python3 -m fhirbug -t https://example.com/fhir \
  --token <access_token> \
  fuzz

# Resource ID enumeration (sequential IDs, 401 vs 404 oracle)
python3 -m fhirbug -t https://example.com \
  --token <access_token> \
  enumeration \
  --endpoints "https://example.com/api/v1/Jobs/{id}" \
              "https://example.com/fhir/Patient/{id}" \
  --known-id <your_known_id>
```

Core bug classes:

1. **Cross-patient IDOR.** Direct resource access (`Patient/{id}`), search
   filter (`Observation?patient={other_id}`), references inside bundles.
   Test with IDs that are YOUR patient ±1, synthetic patient IDs from
   docs, and obvious values like `0`, `-1`, `00000000-0000-...`.

2. **Parameter pollution (HPP).** Send `?patient=X&patient=Y`. Does the
   permission check see one value while the data layer sees another? CMS
   BB2 got this right (last value wins for both). But the CMS server-side
   frameworks can disagree.

3. **Alternate parameter bypass.** Try `subject=X`, `patient.reference=X`,
   `Patient=X` (case), `%20patient=X` (whitespace). A server-side filter
   may recognize one name while the permission check recognizes another.

4. **`_include` / `_revinclude` amplification.** Try `_include=*`,
   `_revinclude=*`, stacked `_revinclude`, recursive `_include:iterate`.
   If these pull additional resource types or unrelated records, report.

5. **`_count` abuse.** Try massive values (999999), zero, negative. The
   server should cap at a reasonable value.

6. **FHIR operation abuse.** Test `/Patient/$everything`, `/$export`,
   `/$graphql`, `/$validate`. Each is a potential mass-exfil vector.

7. **Version history access.** `/Patient/_history` and
   `/Patient/{id}/_history`. Server-level history exposes changes across
   all patients.

8. **Scope enforcement.** If your token has `patient/Observation.read`,
   does `/fhir/Patient` still return data? Real bug: servers issue broad
   tokens and enforce scopes only in the UI layer.

Real example (CMS BB2, CWE-204 near-miss): cross-patient access was
blocked correctly, but the server returned 403 (exists, forbidden) for
EOB queries and 404 (doesn't exist) for Patient direct-read against
other-patient IDs. Looks like an existence oracle at first glance, but on
probe it turned out that every non-self value returned 403 regardless of
whether the patient actually existed. So: code smell, not exploitable.
Worth writing up as LOW/INFO to encourage status-code normalization, but
not a bounty-grade finding. The lesson for hunters: don't call a 401/404
or 403/404 split an oracle until you've probed it with obviously-bogus
IDs that couldn't possibly exist. Half the time it's just
framework-default behavior, not an oracle.

### Phase 6. Bulk Data Export Attacks

Goal: FHIR Bulk Data is a distinct attack surface with its own patterns.

```bash
python3 -m fhirbug -t https://example.com/api/v1 \
  --token <access_token> \
  bulk-export --group-id <your_group_uuid>
```

Attack classes:

1. **Job ID enumeration (401 vs 404 oracle).** The BCDA pattern
   (CWE-204 + CWE-639). Sandbox job IDs were sequential integers
   (84380, 84381, 84382, ...), and the job-status endpoint returned 401
   for "exists but not owned by this ACO" and 404 for "doesn't exist."
   That's an oracle. Step the counter, count the 401s, and you've mapped
   the entire job ledger across all ACOs on the platform, including job
   creation timestamps and approximate size (from `Content-Length` on the
   status response). Reproduces in about 15 minutes with `enumeration
   --endpoints $TARGET/Jobs/{id}` and a range around your own known job
   ID. Real instance: ~1,400 jobs in the BCDA sandbox were enumerable.
   Fix direction: collapse 401 and 404 to a uniform 404 when the caller
   doesn't own the resource, and switch job IDs to UUIDs.

2. **`_type` and `_typeFilter` injection.** The AB2D pattern (CWE-20
   Improper Input Validation). The `_type` parameter was strictly
   validated against a FHIR resource-type allow-list, but `_typeFilter`
   accepted arbitrary strings including SQL-injection payloads, cross-
   resource query expressions, template-injection syntax (`{{7*7}}`),
   and wildcards. Jobs never completed with these payloads (likely
   failing at a later query-validation stage), so we couldn't confirm
   an exploit path. The asymmetry is the tell: two parameters in the
   same operation, one validated strictly, the other not. Eventually
   the unvalidated one reaches something interpretable. Fix direction:
   parse `_typeFilter` through a FHIR-search-parameter-expression
   validator before queuing the job.

3. **File download authorization.** Once a job completes, the server
   hands back a manifest of NDJSON file URLs. The full attack matrix:
   - Can you download without auth? (CWE-306)
   - Can a different tenant's token download your file? (CWE-639)
   - Can you path-traverse within `/data/{job_id}/{file_uuid}.ndjson`? (CWE-22)
   - Are file UUIDs guessable? (CWE-330 if not cryptographically random)
   - Does the file expire, and what happens in the window between job-
     completion and expiration? (CWE-613)
   - Does `requiresAccessToken: false` in the manifest actually mean the
     blob is public, or is it FHIR-layer delegation to storage RBAC? On
     Azure AHDS it's the latter; you have to check the storage layer
     separately.

4. **Cross-org bulk export.** If the export path includes a Group ID
   (`/Group/{id}/$export`), does the server validate that your token
   owns that group? CWE-639 territory. The fuzz here is: kick an export
   on your own group, note the URL shape, then swap the group UUID for a
   known-other-org's group ID (from the enumeration in attack 1 above)
   and see what happens. Rejection should be immediate; if the server
   queues the job, you'll find out later.

5. **Excessive job creation.** Rate limits on job creation, stale job
   cleanup, queue exhaustion. We hit this accidentally on AB2D by
   queueing 30+ jobs trying to isolate a `_typeFilter` behavior. The
   queue filled and nothing completed. Good lesson on rate-limit
   discipline. The adversarial version is worth probing if the target
   hasn't capped concurrent jobs per client.

---

## Bug Class Catalog

Patterns that repeat across healthcare APIs.

### Authentication Layer

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| A1 | Client ID enumeration via response discrepancy | MED, HIGH | `client-enum` |
| A2 | JWT `alg=none` accepted | CRITICAL | `jwt-fuzz` |
| A3 | JWT HS256 key confusion | CRITICAL | `jwt-fuzz` |
| A4 | Public key ID enumeration via error messages | MEDIUM | `error-oracle` |
| A5 | Missing `jti` replay protection | HIGH | `jwt-fuzz` |
| A6 | `iss != sub` not enforced | MEDIUM | `jwt-fuzz` |
| A7 | Wrong `aud` not rejected | MEDIUM | `jwt-fuzz` |
| A8 | Unhandled 500 exceptions in auth endpoints | MEDIUM | `error-oracle`, `jwt-fuzz` |
| A9 | Validation order leaked via distinct errors | LOW | `error-oracle` |
| A10 | Excessive token lifetime (> 1 hour) | LOW, MED | manual JWT inspection |
| A11 | Token-endpoint info leak (stack trace) | MEDIUM | `error-oracle` |
| A12 | Signature stripping accepted | CRITICAL | `jwt-fuzz` |
| A13 | Wrong-key signing accepted | CRITICAL | `jwt-fuzz` |
| A14 | SMART scope escalation via `client_assertion` | HIGH | `jwt-fuzz` |
| A15 | `fhirUser` impersonation accepted | HIGH | `jwt-fuzz` |

### Authorization / Data Layer

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| Z1 | Cross-patient IDOR via direct read | CRITICAL | `fuzz` |
| Z2 | Cross-patient IDOR via search filter | CRITICAL | `fuzz` |
| Z3 | HTTP parameter pollution bypass | CRITICAL | `fuzz` |
| Z4 | Alternate parameter name bypass | CRITICAL | `fuzz` |
| Z5 | `_include=*` pulls unrelated resources | HIGH | `fuzz` |
| Z6 | `_revinclude=*` amplification | HIGH | `fuzz` |
| Z7 | Scope enforcement missing at resource level | HIGH | manual w/ token |
| Z8 | Patient context boundary bypass | CRITICAL | manual w/ token |
| Z9 | Version history cross-patient access | MEDIUM | `fuzz` |
| Z10 | Server-level `_history` exposed | MEDIUM | `fuzz` |

### Bulk Data / Export

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| B1 | Sequential job IDs + 401/404 enumeration | HIGH | `bulk-export`, `enumeration` |
| B2 | `_typeFilter` no validation (injection?) | MED, HIGH | `bulk-export` |
| B3 | Job download URL unauthenticated | CRITICAL | `bulk-export` |
| B4 | Cross-tenant job file download | CRITICAL | `bulk-export` |
| B5 | Path traversal in data file URLs | HIGH | `bulk-export` |
| B6 | Job cancellation cross-tenant | MEDIUM | `bulk-export` |
| B7 | `/jobs` listing hangs / unbounded query | MEDIUM (DoS) | manual |
| B8 | Cached job reuse leaks stale data | MEDIUM | manual (inspect `transactionTime`) |

### CORS

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| C1 | `ACAO: *` + `Authorization` in `ACAH` | HIGH | `cors` |
| C2 | Origin reflection + `ACAC: true` | CRITICAL | `cors` |
| C3 | Missing `Vary: Origin` | LOW | `cors` |
| C4 | CORS allows `null` origin | MEDIUM | `cors` |

### Response / Serialization

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| R1 | HAPI FHIR internal field leak | HIGH | `serialization` |
| R2 | Empty-body amplification (DoS) | MEDIUM | `serialization` |
| R3 | Stack trace leak in error bodies | MED, LOW | `serialization` |
| R4 | Debug headers exposed (`X-Debug`, etc.) | LOW | `fingerprint` |
| R5 | Server / X-Powered-By version leak | INFO | `fingerprint` |

### Fingerprinting / Info Disclosure

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| F1 | Production running `-SNAPSHOT` build | LOW | `fingerprint` |
| F2 | Draft capability statement (old date) | LOW | `fingerprint` |
| F3 | Git commit hash on `/version` | LOW | `fingerprint` |
| F4 | Build timestamp disclosure | LOW | `fingerprint` |
| F5 | Public OpenAPI spec at `/v3/api-docs` | INFO | `fingerprint` |
| F6 | Spring Boot Actuator present | INFO | `fingerprint` |
| F7 | Dynamic client registration open | HIGH (if open) | `auth` |
| F8 | Version disclosure in `software.version` of CapabilityStatement | LOW | `recon` |

### OpenAPI / Documentation

| # | Pattern | Severity | Detection |
|---|---------|----------|-----------|
| D1 | OpenAPI mislabels auth requirements | LOW | `fingerprint` |
| D2 | Sandbox credentials in public docs | INFO | `doc-scrape` |
| D3 | Curl examples reveal auth flow | INFO | `doc-scrape` |

---

## Toolkit Quick Reference

### The canonical attack sequence

```bash
TARGET=https://sandbox.example.com/api/v1
TOKEN=<paste_after_oauth_flow>

# Phase 1: Recon
python3 -m fhirbug -t $TARGET recon -oh reports/recon.html

# Phase 2: Fingerprint (catches F1-F8)
python3 -m fhirbug -t $TARGET fingerprint

# Phase 3: Scrape docs for creds + aux endpoints
python3 -m fhirbug -t $TARGET doc-scrape \
  --urls https://example.com/developer-docs

# Phase 4: Serialization bugs (catches R1-R5)
python3 -m fhirbug -t $TARGET serialization \
  --endpoints $TARGET/metadata $TARGET/Patient $TARGET/Token/validate

# Phase 5: OAuth client enum (A1)
python3 -m fhirbug -t $TARGET client-enum \
  --token-url $TARGET/oauth/token \
  --valid-client-id <known_client>

# Phase 6: Error oracle mapping (A8, A9)
python3 -m fhirbug -t $TARGET error-oracle \
  --token-url $TARGET/oauth/token

# Phase 7: JWT fuzzing (A2-A7, A12-A15) if the target uses JWT client assertions
python3 -m fhirbug -t $TARGET jwt-fuzz \
  --token-url $TARGET/oauth/token \
  --private-key path/to/private.pem \
  --valid-kid <kid> \
  --audience $TARGET/oauth/token

# Phase 8: CORS (C1-C4) generates an HTML PoC on finding
python3 -m fhirbug -t $TARGET cors

# Phase 9: Full data-layer fuzz (requires token, catches Z1-Z10)
python3 -m fhirbug -t $TARGET --token $TOKEN fuzz

# Phase 10: Bulk export (B1-B8)
python3 -m fhirbug -t $TARGET --token $TOKEN \
  bulk-export --group-id <your_group>

# Phase 11: Resource ID enumeration (B1, Z-adjacent)
python3 -m fhirbug -t $TARGET --token $TOKEN \
  enumeration \
  --endpoints "$TARGET/Jobs/{id}" "$TARGET/Group/{id}" \
  --known-id <your_known_id>

# Full scan (recon + fingerprint + auth + serialization + cors + fuzz)
python3 -m fhirbug -t $TARGET --token $TOKEN \
  -oh reports/full.html -oj reports/full.json full
```

### Speedrun commands (for vendor shakedown before investing time)

```bash
# Quick 30-second target profile
python3 -m fhirbug -t $TARGET fingerprint
python3 -m fhirbug -t $TARGET serialization

# If those find anything, escalate to full recon + auth
```

---

## Appendix: CMS Sandbox Registration (How to Obtain Your Own Credentials)

Register your own sandbox credentials via the vendor portals below. Do not
share or reuse another researcher's credentials.

### AB2D (CMS)

- Request access via the CMS ACT portal: <https://ab2d.cms.gov/>, then contact Part D sponsor enrollment
- Once approved, Okta issues client_id plus client_secret pairs (one per contract)
- Token endpoint: `https://test.idp.idm.cms.gov/oauth2/aus2r7y3gdaFMKBol297/v1/token`
- Auth flow: `client_credentials` grant with HTTP Basic auth (`client_id:client_secret`)

### BCDA (CMS)

- Request access via the CMS ACT or BCDA portal
- Token endpoint: `https://sandbox.bcda.cms.gov/auth/token`
- Six ACO credential pairs are provided to registered ACOs; the doc-scrape module extracts them from authenticated portal pages

### Blue Button 2.0 (CMS)

- Sandbox base: `https://sandbox.bluebutton.cms.gov`
- Self-service account registration: `https://sandbox.bluebutton.cms.gov/v2/accounts/create`
- Synthetic beneficiary logins are published by CMS: `BBUser00000` through `BBUser10000` with passwords `PW00000!` through `PW10000!` (these are publicly documented test identities)
- OAuth client registration: `https://sandbox.bluebutton.cms.gov/v2/o/applications/register/`

### DPC (CMS)

- Self-service sandbox signup: `https://sandbox.dpc.cms.gov/users/sign_up`
- Token endpoint: `https://sandbox.dpc.cms.gov/api/v1/Token/auth`
- Synthetic beneficiary MBIs sourced from BFD test data (one confirmed working: `1S00E00JJ00`)
- Registration flow: self-register, upload RSA keypair, sign snippet challenge, receive client token, then use in the `private_key_jwt` assertion flow

Security note: sandbox credentials issued to you are scoped to your
account. Do not commit them to version control. Use environment files
(excluded in `.gitignore`) or a secrets manager.

---

## Appendix: Flexpa Endpoint Directory

Free, real-time directory of 488+ payer FHIR endpoints across 320+ payers:
<https://www.flexpa.com/docs/network/directory>

Automated sweep (use sparingly, respect rate limits):

```bash
# Scrape the directory
python3 -m fhirbug -t https://flexpa.com doc-scrape \
  --urls https://www.flexpa.com/docs/network/directory

# Then fingerprint each endpoint
for url in $(cat payer_endpoints.txt); do
  python3 -m fhirbug -t "$url" fingerprint
  sleep 2
done
```

---

This playbook is a living document. Update it as new patterns emerge.
Current version: v1.0.
