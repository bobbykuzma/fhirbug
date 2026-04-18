"""DPC (Data at the Point of Care) authentication module.

DPC uses a custom JWT-based auth flow:
1. Developer uploads RSA public key via portal
2. Server returns public_key_id (kid)
3. Developer issues a client_token via portal (the iss/sub identifier)
4. Developer signs a JWT with private key (RS384, kid=public_key_id)
5. POSTs JWT to /api/v1/Token/auth as client_assertion
6. Server validates JWT, returns 5-min access token
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from rich.console import Console

console = Console()

DPC_BASE = "https://sandbox.dpc.cms.gov"
TOKEN_AUTH_URL = f"{DPC_BASE}/api/v1/Token/auth"
TOKEN_AUDIENCE = TOKEN_AUTH_URL  # the JWT aud claim must match this exactly


@dataclass
class DPCConfig:
    base_url: str = DPC_BASE
    client_token: str = ""        # the iss/sub identifier from the DPC portal
    public_key_id: str = ""       # the kid for the JWT header
    private_key_path: str = ""    # path to PEM-encoded RSA private key
    public_key_path: str = ""     # path to PEM-encoded RSA public key


def load_private_key(path: str):
    """Load an RSA private key from a PEM file."""
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=None,
    )


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_jwt_rs384(
    payload: dict[str, Any],
    header: dict[str, Any],
    private_key,
) -> str:
    """Sign a JWT with RS384."""
    header_b64 = base64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA384(),
    )

    return f"{header_b64}.{payload_b64}.{base64url(signature)}"


def make_dpc_jwt(
    config: DPCConfig,
    *,
    iss: str | None = None,
    sub: str | None = None,
    aud: str = TOKEN_AUDIENCE,
    exp_offset: int = 300,
    jti: str | None = None,
    extra_payload: dict[str, Any] | None = None,
    extra_header: dict[str, Any] | None = None,
    alg: str = "RS384",
    kid: str | None = None,
) -> str:
    """Generate a DPC JWT.

    Defaults match the DPC spec but every field is overridable for fuzzing.
    """
    private_key = load_private_key(config.private_key_path)

    header = {
        "alg": alg,
        "kid": kid if kid is not None else config.public_key_id,
    }
    if extra_header:
        header.update(extra_header)

    now = int(time.time())
    payload = {
        "iss": iss if iss is not None else config.client_token,
        "sub": sub if sub is not None else config.client_token,
        "aud": aud,
        "exp": now + exp_offset,
        "iat": now,
        "jti": jti if jti is not None else str(uuid.uuid4()),
    }
    if extra_payload:
        payload.update(extra_payload)

    return sign_jwt_rs384(payload, header, private_key)


def request_dpc_token(
    config: DPCConfig,
    jwt_assertion: str | None = None,
    scope: str = "system/*.*",
) -> httpx.Response:
    """POST a JWT to /api/v1/Token/auth and return the response."""
    if jwt_assertion is None:
        jwt_assertion = make_dpc_jwt(config)

    with httpx.Client(timeout=30, http2=True) as c:
        return c.post(
            f"{config.base_url}/api/v1/Token/auth",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "client_credentials",
                "scope": scope,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": jwt_assertion,
            },
        )


def sign_snippet_for_key_upload(
    snippet_path: str,
    private_key_path: str,
    output_path: str,
) -> str:
    """Sign a snippet.txt with SHA256+PKCS1v15 (per DPC docs).

    Returns the base64-encoded signature.
    """
    private_key = load_private_key(private_key_path)
    snippet = Path(snippet_path).read_bytes()

    signature = private_key.sign(
        snippet,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    sig_b64 = base64.b64encode(signature).decode()
    Path(output_path).write_text(sig_b64)
    return sig_b64
