from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    """Simple token-bucket style limiter: max_rps across callers sharing this instance."""

    def __init__(self, max_rps: float = 5.0) -> None:
        self.max_rps = max(0.1, float(max_rps))
        self._min_interval = 1.0 / self.max_rps
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self._min_interval
