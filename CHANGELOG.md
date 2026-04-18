# Changelog

All notable changes to `fhirbug` will be documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## 0.1.0 (2026-04-17)

Initial public release.

### Modules

- **Recon.** `recon` (capability statement + SMART config discovery),
  `fingerprint` (server stack identification), `doc-scrape` (credential
  extraction from vendor developer-portal pages), `error_oracles`.
- **Auth.** `client_enum` (OAuth client ID enumeration via response
  discrepancy, CWE-204), `cors_tester` (multi-origin probing + HTML PoC
  generation), `jwt_fuzzer` (10 attack classes: alg confusion, kid
  manipulation, claim manipulation, jti replay, structural malformation,
  signature stripping, wrong-key signing, alg case variants, header key
  injection, SMART scope escalation), `smart_scanner` (SMART-on-FHIR
  discovery + posture analysis), `dpc`, `flow`, `scopes`, `smart`,
  `tokens`.
- **Fuzz.** `enumeration` (sequential-ID + 401/404 oracle detection),
  `serialization` (HAPI internal-field leak + response-size amplification
  detection, with WAF / intermediary filtering), `bulk_export` (Bulk Data
  `$export` + `_typeFilter` injection), `provenance` (X-Provenance header
  fuzzing), `search` (SQL / NoSQL / SSTI / path-traversal with
  benign-baseline diffing), `includes`, `references`, `injection`.
- **Core.** `client` (async httpx wrapper), `config` (target + SMART scopes
  + search-param catalog), `models` (Finding / ScanResult / Severity /
  FindingCategory).
- **Reporting.** JSON + HTML output.

### CLI Subcommands

`recon`, `fingerprint`, `auth`, `cors`, `client-enum`, `jwt-fuzz`,
`serialization`, `enumeration`, `bulk-export`, `doc-scrape`, `error-oracle`,
`provenance`, `fuzz`, `full`.

### Examples

- `examples/smart_config_survey.py`. Cross-vendor SMART discovery survey
  runner with configurable target list.
- `examples/smart_authorize_probes.py`. Active PKCE / state / scope probes
  against SMART authorize endpoints.

### Documentation

- `PLAYBOOK.md`. Six-phase FHIR security testing methodology (50+ bug
  patterns).
- `TOOLKIT.md`. Module-by-module reference.
- `README.md`. Installation, quickstart, safety posture.
- `SECURITY.md`. Vulnerability disclosure policy for toolkit bugs.

### Provenance

Developed during a cross-vendor healthcare FHIR security research
engagement. Three attack-class modules (`client_enum`, `serialization`,
`jwt_fuzzer`) were built directly from confirmed findings during the
engagement. Full engagement writeup pending coordinated disclosure with
affected vendors.
