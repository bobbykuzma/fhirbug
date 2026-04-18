"""Async HTTP client with rate limiting and error handling."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .config import TargetConfig


class FHIRClient:
    """HTTP client tuned for FHIR endpoint testing."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        self._last_request_time: float = 0
        self._client: httpx.AsyncClient | None = None
        self.request_count = 0
        self.error_count = 0

    async def __aenter__(self) -> FHIRClient:
        transport_kwargs: dict[str, Any] = {}
        if self.config.proxy:
            transport_kwargs["proxy"] = self.config.proxy

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            verify=self.config.verify_ssl,
            follow_redirects=True,
            http2=True,
            **transport_kwargs,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def _rate_limit(self) -> None:
        if self.config.rate_limit > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self.config.rate_limit:
                await asyncio.sleep(self.config.rate_limit - elapsed)
        self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        raw_body: str | None = None,
    ) -> httpx.Response:
        """Send an HTTP request with rate limiting and concurrency control."""
        async with self._semaphore:
            await self._rate_limit()
            merged_headers = dict(self.config.auth_headers)
            if headers:
                merged_headers.update(headers)

            self.request_count += 1
            assert self._client is not None

            kwargs: dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": merged_headers,
            }
            if params:
                kwargs["params"] = params
            if json_body is not None:
                kwargs["json"] = json_body
            elif raw_body is not None:
                kwargs["content"] = raw_body

            try:
                return await self._client.request(**kwargs)
            except httpx.HTTPError:
                self.error_count += 1
                raise

    async def get(
        self,
        url: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self.request("GET", url, headers=headers, params=params)

    async def post(
        self,
        url: str,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self.request("POST", url, headers=headers, json_body=json_body)

    async def put(
        self,
        url: str,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self.request("PUT", url, headers=headers, json_body=json_body)

    async def delete(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self.request("DELETE", url, headers=headers)

    async def get_json(
        self, url: str, params: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        """GET and parse JSON, returning None on failure."""
        try:
            resp = await self.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
        except (httpx.HTTPError, ValueError):
            pass
        return None
