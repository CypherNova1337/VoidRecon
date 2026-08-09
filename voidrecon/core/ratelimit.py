"""Async rate limiting and concurrency control.

An attacker who wants to stay unnoticed does not hammer a target. VoidRecon
throttles every active request through a shared token bucket with optional jitter,
and caps concurrency with a semaphore. Both are per-run and shared across modules.
"""

from __future__ import annotations

import asyncio
import random
import time


class RateLimiter:
    """Token-bucket limiter. ``rate`` is tokens/sec; ``jitter`` adds +/- delay."""

    def __init__(self, rate: float = 8.0, jitter: float = 0.0):
        self.rate = max(rate, 0.1)
        self.jitter = max(0.0, min(jitter, 1.0))
        self._min_interval = 1.0 / self.rate
        self._next_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next_time - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            interval = self._min_interval
            if self.jitter:
                interval *= 1.0 + random.uniform(-self.jitter, self.jitter)
            self._next_time = now + max(interval, 0.0)


class ConcurrencyGuard:
    """A thin wrapper over :class:`asyncio.Semaphore` for readable ``async with``."""

    def __init__(self, limit: int = 20):
        self._sem = asyncio.Semaphore(max(1, limit))

    async def __aenter__(self):
        await self._sem.acquire()
        return self

    async def __aexit__(self, *exc):
        self._sem.release()
        return False
