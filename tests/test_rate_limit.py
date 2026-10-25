import asyncio
import time

import pytest

from vuln_agent.tools.rate_limit import AsyncRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_spaces_calls():
    limiter = AsyncRateLimiter(max_rps=5.0)  # 200ms between acquires
    start = time.monotonic()

    async def one():
        await limiter.acquire()

    await asyncio.gather(*[one() for _ in range(3)])
    elapsed = time.monotonic() - start
    # 3 acquires at 5 rps → at least ~0.4s between first and third spacing
    assert elapsed >= 0.35
