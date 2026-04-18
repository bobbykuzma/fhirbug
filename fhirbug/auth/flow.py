"""SMART on FHIR / OAuth 2.0 authorization code flow runner with PKCE.

Stands up a local HTTP server to catch the redirect, opens a browser to the
authorization endpoint, and exchanges the resulting code for an access token.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console

console = Console()


@dataclass
class TokenResult:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_token: str = ""
    scope: str = ""
    patient: str = ""
    id_token: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
        console.print(f"[green]Token saved to:[/] {path}")

    @classmethod
    def load(cls, path: str) -> TokenResult:
        data = json.loads(Path(path).read_text())
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 0),
            refresh_token=data.get("refresh_token", ""),
            scope=data.get("scope", ""),
            patient=data.get("patient", ""),
            id_token=data.get("id_token", ""),
            raw=data.get("raw", {}),
            issued_at=data.get("issued_at", ""),
        )


def generate_pkce() -> tuple[str, str]:
    """Generate a PKCE code_verifier and S256 code_challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """One-shot HTTP handler that captures the OAuth callback."""

    server_version = "FHIR-Toolkit/0.1"
    captured: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # Capture all query parameters
        for k, v in params.items():
            _CallbackHandler.captured[k] = v[0] if v else ""

        # Send a friendly response
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        if "error" in params:
            err = params["error"][0]
            desc = params.get("error_description", [""])[0]
            body = f"""<html><body style="font-family:sans-serif;background:#0f172a;color:#fee;padding:40px">
<h1>Authorization Error</h1>
<p><b>{err}</b></p>
<p>{desc}</p>
<p>You can close this window.</p>
</body></html>"""
        else:
            body = """<html><body style="font-family:sans-serif;background:#0f172a;color:#dfd;padding:40px">
<h1>Authorization successful</h1>
<p>Code captured. Returning to terminal.</p>
<p>You can close this window.</p>
</body></html>"""
        self.wfile.write(body.encode())

    def log_message(self, format: str, *args: Any) -> None:
        # Silence default access logging
        pass


def _start_callback_server(host: str, port: int) -> tuple[http.server.HTTPServer, threading.Thread]:
    server = http.server.HTTPServer((host, port), _CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def run_authorization_code_flow(
    client_id: str,
    client_secret: str,
    auth_base: str,
    redirect_uri: str,
    scopes: list[str],
    auth_path: str = "/v2/o/authorize/",
    token_path: str = "/v2/o/token/",
    extra_auth_params: dict[str, str] | None = None,
    open_browser: bool = True,
    timeout: int = 300,
) -> TokenResult:
    """Run a full OAuth 2.0 authorization code + PKCE flow.

    Returns a TokenResult with access_token and (if applicable) refresh_token.
    """
    # Parse the redirect URI to set up the local server
    parsed = urllib.parse.urlparse(redirect_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 8000

    # Generate PKCE
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    # Build the authorization URL
    auth_url = auth_base.rstrip("/") + auth_path
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    if extra_auth_params:
        auth_params.update(extra_auth_params)

    full_auth_url = f"{auth_url}?{urllib.parse.urlencode(auth_params)}"

    # Start the local callback server
    console.print(f"[cyan]Starting callback server on[/] {host}:{port}")
    _CallbackHandler.captured = {}
    server, thread = _start_callback_server(host, port)

    try:
        console.print(f"\n[cyan]Authorization URL (copy this exact line):[/]")
        # Print without rich wrapping/coloring so copy-paste is reliable
        print(full_auth_url, flush=True)
        print()

        if open_browser:
            console.print("[cyan]Opening browser...[/]")
            webbrowser.open(full_auth_url)
        else:
            console.print("[yellow]Open the URL above in your browser to complete the flow.[/]")

        # Wait for the callback
        console.print(f"[cyan]Waiting for callback (timeout={timeout}s)...[/]")
        import time
        deadline = time.time() + timeout
        while not _CallbackHandler.captured and time.time() < deadline:
            time.sleep(0.2)

        if not _CallbackHandler.captured:
            raise TimeoutError(f"No callback received within {timeout} seconds")

        captured = _CallbackHandler.captured

        if "error" in captured:
            err = captured.get("error", "")
            desc = captured.get("error_description", "")
            raise RuntimeError(f"Authorization error: {err} - {desc}")

        # Verify state
        returned_state = captured.get("state", "")
        if returned_state != state:
            console.print(
                f"[yellow]WARNING: state mismatch. Sent '{state}', got '{returned_state}'[/]"
            )

        code = captured.get("code", "")
        if not code:
            raise RuntimeError(f"No code in callback. Got: {captured}")

        console.print(f"[green]Authorization code received[/] (length={len(code)})")

    finally:
        server.shutdown()
        server.server_close()

    # Exchange code for token
    token_url = auth_base.rstrip("/") + token_path
    console.print(f"\n[cyan]Exchanging code at[/] {token_url}")

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }

    # Use HTTP Basic auth for confidential clients
    auth = (client_id, client_secret) if client_secret else None

    with httpx.Client(timeout=30, http2=True) as c:
        resp = c.post(
            token_url,
            data=token_data,
            auth=auth,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    if resp.status_code != 200:
        raise RuntimeError(
            f"Token exchange failed: {resp.status_code}\n{resp.text}"
        )

    body = resp.json()
    console.print(f"[green]Token received![/]")

    return TokenResult(
        access_token=body.get("access_token", ""),
        token_type=body.get("token_type", "Bearer"),
        expires_in=body.get("expires_in", 0),
        refresh_token=body.get("refresh_token", ""),
        scope=body.get("scope", ""),
        patient=body.get("patient", ""),
        id_token=body.get("id_token", ""),
        raw=body,
    )


def refresh_token_flow(
    client_id: str,
    client_secret: str,
    auth_base: str,
    refresh_token: str,
    token_path: str = "/v2/o/token/",
) -> TokenResult:
    """Use a refresh token to get a new access token."""
    token_url = auth_base.rstrip("/") + token_path
    console.print(f"[cyan]Refreshing token at[/] {token_url}")

    auth = (client_id, client_secret) if client_secret else None

    with httpx.Client(timeout=30, http2=True) as c:
        resp = c.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
            auth=auth,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    if resp.status_code != 200:
        raise RuntimeError(f"Refresh failed: {resp.status_code}\n{resp.text}")

    body = resp.json()
    return TokenResult(
        access_token=body.get("access_token", ""),
        token_type=body.get("token_type", "Bearer"),
        expires_in=body.get("expires_in", 0),
        refresh_token=body.get("refresh_token", refresh_token),
        scope=body.get("scope", ""),
        patient=body.get("patient", ""),
        raw=body,
    )
