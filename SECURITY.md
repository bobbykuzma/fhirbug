# Security Policy

## Reporting Vulnerabilities in This Toolkit

If you discover a security vulnerability *in the toolkit itself* (not in a
target you've scanned), please report it responsibly rather than opening a
public GitHub issue.

**Contact:** open a private GitHub Security Advisory at
<https://github.com/bobbykuzma/fhirbug/security/advisories/new>, or email
the maintainer directly.

**What qualifies as a toolkit vulnerability:**

- Code execution via crafted JWT or FHIR response handling in toolkit modules
- Dependency vulnerabilities (via `pip install`) with demonstrable impact
- Accidental credential leakage via toolkit logs or evidence capture
- SSRF or path-traversal via toolkit's own configuration loading

**What does NOT qualify:**

- Findings produced BY the toolkit against target FHIR servers. Those
  should be reported to the respective target vendor via their disclosure
  channel.
- Rate-limit concerns with the toolkit's default concurrency settings
  (open a regular issue).

## Responsible Use

This toolkit is intended for security research against FHIR endpoints you
are **authorized to test**. Authorized contexts include:

- Your own infrastructure
- Sandbox or test environments of vendors with published bug-bounty or
  vulnerability-disclosure programs, within the published scope
- Research engagements with written authorization from the target organization

Running this toolkit against production healthcare infrastructure without
authorization may violate the Computer Fraud and Abuse Act (CFAA), HIPAA,
and equivalent laws in your jurisdiction. The authors disclaim all
liability for misuse.

## Safe Testing Posture

The toolkit ships with the following defensive defaults:

- **Rate limiting.** Modules enforce per-target request pacing.
- **Halt on 429 / 403.** Probes stop automatically on rate-limit or WAF
  signatures rather than amplifying load.
- **No credential brute force.** No module attempts to crack passwords or
  client secrets.
- **No PHI handling.** The toolkit captures no patient data; all probes
  use synthetic or obviously fake resource identifiers.
- **False-positive discipline.** Search injection, serialization, and
  CORS modules baseline benign responses before flagging findings.

When extending the toolkit, preserve these defaults.
