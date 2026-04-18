# fhirbug

**An offensive-security testing toolkit for FHIR (Fast Healthcare Interoperability Resources) servers.**

Python 3.11+ · async · MIT-licensed · 14 CLI subcommands across recon, auth, fuzzing, and reporting.

---

## What it does

`fhirbug` is a coordinated set of security-testing modules for HL7 FHIR
servers and the OAuth / SMART-on-FHIR infrastructure around them. It was
built during a cross-vendor healthcare FHIR research engagement (14+
production / sandbox stacks across CMS programs, major EHR vendors, payer
Patient Access APIs, and FHIR middleware aggregators) and codifies real
attack patterns discovered during that engagement into reusable modules.

**Attack-class coverage:**

- **OAuth client-ID enumeration** via response-discrepancy oracles
  (CWE-204, RFC 6749 §5.2 gaps). Detects the specific pattern that
  affected 7 of 14 OAuth stacks we tested in production healthcare APIs.
- **JWT algorithm, claim, and signature attacks.** 10 attack classes
  covering `alg=none`, HS/RS confusion, kid manipulation, signature
  stripping, wrong-key signing, algorithm case variants, header key
  injection (jwk, jku, x5c, x5u, including AWS IMDS SSRF probes), SMART
  scope escalation, and `fhirUser` impersonation.
- **SMART-on-FHIR discovery and active probing.** Cross-vendor comparison
  of `.well-known/smart-configuration` posture, PKCE advertising, scope
  sets, capability flags, plus active authorize-endpoint probes for
  PKCE, state, and scope enforcement.
- **CORS misconfiguration.** Multi-origin probing, wildcard-with-auth
  detection, automatic HTML PoC generation.
- **HAPI FHIR internal-field serialization leaks.**
  `formatCommentsPre` / `formatCommentsPost` / `userData` /
  `valueAsString` with DoS-amplification detection and WAF /
  intermediary filtering.
- **Bulk Data `$export`.** `_typeFilter` injection and scope-enforcement
  testing.
- **FHIR search-parameter injection.** SQLi, NoSQL, SSTI, path traversal,
  each with benign-baseline diffing to eliminate WAF and error-page false
  positives.
- **Sequential-ID + 401/404 oracle** enumeration on multi-tenant FHIR hosts.
- **`X-Provenance` header fuzzing.** A FHIR-specific attack surface.

---

## Installation

```bash
git clone https://github.com/bobbykuzma/fhirbug.git
cd fhirbug
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Verify:

```bash
python3 -m fhirbug --help
```

---

## Quickstart

**1. Recon a FHIR base URL**

```bash
python3 -m fhirbug --target https://fhir.example.com/R4 recon
```

**2. Cross-vendor SMART discovery survey** (edit the TARGETS list in the
example to scope the probe)

```bash
python3 examples/smart_config_survey.py
```

**3. OAuth client enumeration probe**

```bash
python3 -m fhirbug --target https://auth.example.com/oauth/token client-enum
```

**4. JWT fuzz against a private_key_jwt token endpoint** (see
`examples/` for end-to-end runners with cred-loading)

**5. Full battery** (all applicable modules for a target)

```bash
python3 -m fhirbug --target https://fhir.example.com/R4 \
  --output-json out.json --output-html out.html full
```

See `TOOLKIT.md` for the full module + CLI reference and `PLAYBOOK.md` for
the six-phase testing methodology.

---

## Safety + authorized-use posture

**This toolkit is intended for authorized security research only.**

Defensive defaults:

- Rate limiting per target (≤ toolkit-configured rps)
- Halt on 429 / 403 / WAF signatures rather than amplify load
- Benign-baseline diffing on injection probes to eliminate false
  positives from WAF error pages
- No PHI handling. Probes use synthetic or obviously fake resource
  identifiers.
- No credential brute force. No password or secret cracking modules.

**Legal posture:** running this against production healthcare
infrastructure without authorization may violate the Computer Fraud and
Abuse Act (CFAA), HIPAA, and equivalent laws in your jurisdiction. See
`SECURITY.md` for more.

**Authorized contexts:**

- Your own infrastructure.
- Sandbox environments of vendors with published bug-bounty or VDP
  programs (CMS Bugcrowd BBP, HackerOne VDPs for Cigna, Elevance,
  Kaiser, UHG, MSRC Azure Bounty, and others), within the published
  scope.
- Research engagements with written authorization from the target
  organization.

---

## Provenance

Three attack-class modules (`client_enum`, `serialization`, `jwt_fuzzer`)
were built directly from confirmed findings during a cross-vendor healthcare
FHIR research engagement. Full engagement writeup will be published after
coordinated disclosure with affected vendors completes. The methodology in
`PLAYBOOK.md` reflects lessons from that engagement.

If you're a vendor whose product this toolkit is likely to be pointed at,
reach out via your published security disclosure channel. We coordinate
disclosures on a 90-day default timeline.

---

## Contributing

Issues and pull requests welcome. The module-boundary conventions are
documented in `TOOLKIT.md` under "Design Principles." New attack-class
modules should:

- Include a docstring with the CWE / CVE reference (if applicable) for the
  class of vulnerability being tested
- Implement benign-baseline or duplicate-response filtering to suppress
  false positives from WAFs / intermediaries
- Respect the rate-limit discipline (no bursting)
- Include at least one test vector that distinguishes a true positive from
  the common false-positive shape

---

## License

MIT. See `LICENSE`.

## Author

Bobby Kuzma. Healthcare FHIR security research.
