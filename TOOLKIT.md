# FHIR Recon & Fuzzing Toolkit

A FHIR-specific security testing toolkit, built and hardened during
active bug-bounty research against the CMS FHIR ecosystem (Blue Button
2.0, AB2D, BCDA, DPC).

## Modules

### Reconnaissance
- **`recon/capability.py`**. Parses the `/metadata` CapabilityStatement.
  Detects software version, vendor, supported resources, write operations,
  SMART on FHIR security scheme, and high-risk operations (`$everything`,
  `$export`, `$graphql`).
- **`recon/endpoints.py`**. Probes resource endpoints for accessibility,
  unauthenticated access, and record counts.
- **`recon/smart_config.py`**. Discovers and analyzes SMART on FHIR
  configuration: grant types, scopes, PKCE support, dynamic client
  registration.
- **`recon/fingerprint.py`** ⭐. Deep stack fingerprinting. Detects frameworks
  (HAPI FHIR, Spring Boot, Django OAuth Toolkit, Dropwizard, IdentityServer4,
  Rails Devise), build versions, git commit hashes, `-SNAPSHOT` dev builds,
  draft capability statements, Swagger/OpenAPI leaks, Spring Boot Actuator
  endpoints.
- **`recon/doc_scraper.py`** ⭐. Automated credential + endpoint extraction
  from vendor API documentation. Finds UUIDs, 32-256 char hex secrets,
  paired `(client_id, secret)` tuples, token endpoints, FHIR base URLs,
  curl examples. Works on any vendor docs page.
- **`recon/error_oracles.py`** ⭐. Maps server validation order by probing
  a token endpoint with 15+ crafted JWTs, each designed to trigger a
  specific validation step. Reports distinct error messages, detects
  framework fingerprints from error text, flags unhandled 500 exceptions.

### Authentication & Authorization
- **`auth/tokens.py`**. JWT inspection: algorithm, claims, lifetime,
  scope analysis.
- **`auth/smart.py`**. SMART on FHIR flow testing: token endpoint probing,
  dynamic client registration, verbose error detection.
- **`auth/scopes.py`**. Scope enforcement + patient context boundary testing.
- **`auth/flow.py`**. OAuth 2.0 authorization code + PKCE flow runner with
  local callback server.
- **`auth/dpc.py`**. CMS DPC-specific JWT signing with RSA private key.
- **`auth/client_enum.py`** ⭐. Detects OAuth client ID enumeration via
  response discrepancies on token / authorize endpoints (CWE-204, RFC 6749
  §5.2 violation).
- **`auth/jwt_fuzzer.py`** ⭐. JWT attack suite: `alg=none`,
  HS/RS/ES/PS algorithm confusion, kid manipulation, claim fuzzing (`exp`,
  `iss`, `sub`, `client_id`, `jti`), jti replay detection, structural
  attacks, signature stripping, wrong-key signing, alg case variants,
  header key injection (jwk, jku, x5c, x5u), SMART scope escalation,
  `fhirUser` impersonation.
- **`auth/cors_tester.py`** ⭐. Multi-origin CORS probe + automatic HTML PoC
  generation for `ACAO: *` + `Authorization` header exfil scenarios.

### Fuzzing
- **`fuzz/search.py`**. Search parameter injection (SQL, NoSQL, SSTI, path
  traversal), FHIR-specific abuse (`_count` overflow, `_filter`, chained
  search, `_has`).
- **`fuzz/includes.py`**. `_include` / `_revinclude` amplification and
  recursive `_include:iterate`.
- **`fuzz/references.py`**. Reference traversal (IDOR), ID predictability,
  version history access.
- **`fuzz/injection.py`**. FHIR-specific injection: content-type abuse,
  header injection, `$validate`/`$everything`/`$export` operation testing.
- **`fuzz/enumeration.py`** ⭐. Resource ID enumeration oracle detection.
  Probes for sequential integer IDs, binary searches the ID range, detects
  401 vs 404 response discrepancy that enables cross-tenant mapping.
- **`fuzz/serialization.py`** ⭐. Response serialization bug detection:
  HAPI FHIR internal field leak (`formatCommentsPre`/`Post`), empty-body
  response amplification (DoS), stack trace leakage.
- **`fuzz/bulk_export.py`** ⭐. FHIR Bulk Data `$export` flow testing:
  job initiation, `_typeFilter` injection fuzzing, cross-tenant job
  enumeration, file download auth + path traversal.
- **`fuzz/provenance.py`** ⭐. JSON-in-header fuzzer. Tests X-Provenance
  style headers (FHIR Provenance resource in an HTTP header) for missing
  field handling, cross-tenant agent claims, JSON parser abuse, CRLF
  injection, oversized payloads, Content-Type confusion.

### Core
- **`core/client.py`**. Async HTTP client with rate limiting, concurrency
  control, HTTP/2.
- **`core/config.py`**. Target configuration, FHIR resource catalogs,
  search parameter wordlists, SMART scope lists.
- **`core/models.py`**. Data models: `Finding`, `Severity`, `EndpointInfo`,
  `ScanResult`.

### Reporting
- **`report/generator.py`**. JSON + HTML report output with severity
  color-coding.

---

## CLI Subcommands

```
python3 -m fhirbug -t <URL> <command>

Commands:
  recon          Reconnaissance only
  fingerprint    Deep stack fingerprinting
  auth           Auth / authz testing (tokens, scopes, registration)
  cors           CORS misconfiguration + PoC generator
  client-enum    OAuth client ID enumeration detection
  jwt-fuzz       JWT algorithm + claim fuzzing
  serialization  Response serialization bug detection
  enumeration    Resource ID enumeration oracle (401 vs 404)
  bulk-export    FHIR Bulk Data $export flow testing
  doc-scrape     Scrape vendor API docs for credentials + endpoints
  error-oracle   Map validation order via error message probes
  provenance     JSON-in-header fuzzer (X-Provenance style)
  fuzz           Search / include / reference fuzzing
  full           Full scan (all phases)
```

## Star Modules (built from real findings)

⭐ indicates a module codified directly from a confirmed bug bounty finding:

| Module | Source Finding |
|--------|---------------|
| `recon/fingerprint.py` | DPC `0.4.0-SNAPSHOT` from 2019; BCDA `/_version r285`; DPC git commit leak |
| `recon/doc_scraper.py` | CMS BCDA 6 sandbox credential pairs inline in docs; AB2D contract auth pairs |
| `recon/error_oracles.py` | CMS DPC 8+ distinct JWT validation error messages |
| `auth/client_enum.py` | CMS BB2 `/v2/o/token/` client ID enumeration (HIGH) |
| `auth/jwt_fuzzer.py` | CMS DPC JWT validation order leak + 5 unhandled exceptions |
| `auth/cors_tester.py` | CMS BB2 `ACAO: *` + `Authorization` header PHI exfil (HIGH) |
| `fuzz/enumeration.py` | CMS BCDA sequential job IDs + 401/404 oracle (HIGH) |
| `fuzz/serialization.py` | CMS DPC HAPI FHIR internal field leak + 168KB amplification (HIGH) |
| `fuzz/bulk_export.py` | CMS AB2D `_typeFilter` no validation (MEDIUM) |
| `fuzz/provenance.py` | CMS DPC X-Provenance header validation chain + cross-tenant tests |

## Smoke Test Against DPC Sandbox

```bash
# Fingerprint, auto-reproduces CMS DPC findings:
#   0.4.0-SNAPSHOT build, draft capability, git commit leak
python3 -m fhirbug -t "https://sandbox.dpc.cms.gov/api/v1" fingerprint

# Serialization, auto-reproduces DPC HAPI leak + 168KB amplification:
python3 -m fhirbug -t "https://sandbox.dpc.cms.gov/api/v1" serialization \
  --endpoints "https://sandbox.dpc.cms.gov/api/v1/Token/validate" \
              "https://sandbox.dpc.cms.gov/api/v1/Token/auth"
```

## Design Principles

1. **Each finding we spend time on in the field becomes a reusable module.**
2. **Modules should detect without requiring target-specific configuration.**
   The enumeration module figures out if IDs are sequential or UUIDs; the
   CORS tester generates a working PoC without hardcoded targets.
3. **Findings carry remediation advice** extracted from real CMS reports.
4. **False positive resistance matters more than false negative sensitivity.**
   The toolkit should not cry wolf; when it reports a finding, it's
   well-evidenced.
5. **Run against any target, not just CMS.** Modules accept the target as
   CLI argument and don't hardcode CMS-specific URLs.
