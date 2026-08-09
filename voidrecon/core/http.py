"""Shared async HTTP client with retries, throttling, and UA rotation.

Every outbound request — whether to a passive OSINT API or (when active mode is
on) to the target itself — flows through :class:`HttpClient`, so rate limiting,
timeouts, and user-agent hygiene are applied uniformly.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from voidrecon.core.logging import get_logger
from voidrecon.core.ratelimit import ConcurrencyGuard, RateLimiter

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

log = get_logger("http")


class HttpClient:
    def __init__(
        self,
        *,
        user_agent: str,
        rate: float = 8.0,
        jitter: float = 0.0,
        concurrency: int = 20,
        timeout: float = 20.0,
        retries: int = 2,
        verify_tls: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        rotate_user_agents: bool = True,
        auth_headers: dict | None = None,
        auth_cookies: dict | None = None,
    ):
        self._default_ua = user_agent
        self._rotate = rotate_user_agents
        self._retries = max(0, retries)
        self._limiter = RateLimiter(rate=rate, jitter=jitter)
        self._guard = ConcurrencyGuard(concurrency)
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        base_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if auth_headers:
            # Authenticated-session headers (Authorization, custom) sent on every request.
            base_headers.update(auth_headers)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            limits=limits,
            headers=base_headers,
            cookies=auth_cookies or None,
        )

    def _ua(self) -> str:
        if self._rotate:
            return random.choice(_UA_POOL)
        return self._default_ua

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("User-Agent", self._ua())
        attempt = 0
        backoff = 1.0
        while True:
            await self._limiter.acquire()
            try:
                async with self._guard:
                    return await self._client.request(method, url, headers=headers, **kwargs)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self._retries:
                    log.debug("request failed after retries: %s %s (%s)", method, url, exc)
                    return None
                await asyncio.sleep(backoff + random.uniform(0, 0.5))
                backoff *= 2
                attempt += 1
            except httpx.HTTPError as exc:
                log.debug("http error: %s %s (%s)", method, url, exc)
                return None
            except (ValueError, TypeError) as exc:
                # Malformed URL / unsupported scheme must never crash a module.
                log.debug("bad request skipped: %s %s (%s)", method, url, exc)
                return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def get_json(self, url: str, **kwargs: Any) -> Any | None:
        resp = await self.get(url, **kwargs)
        if resp is None or resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except Exception:
            return None

    async def get_text(self, url: str, **kwargs: Any) -> str | None:
        resp = await self.get(url, **kwargs)
        if resp is None or resp.status_code >= 400:
            return None
        return resp.text

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> bool:
        await self.aclose()
        return False
