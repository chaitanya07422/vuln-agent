from __future__ import annotations

import time
from typing import Optional


class RefreshStore:
    """Track valid refresh JTIs (Redis or memory)."""

    async def put(self, jti: str, user_id: str, ttl_sec: int) -> None:
        raise NotImplementedError

    async def pop(self, jti: str) -> Optional[str]:
        """Return user_id if valid and remove (rotate)."""
        raise NotImplementedError

    async def revoke(self, jti: str) -> None:
        raise NotImplementedError


class MemoryRefreshStore(RefreshStore):
    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}

    async def put(self, jti: str, user_id: str, ttl_sec: int) -> None:
        self._data[jti] = (user_id, time.time() + ttl_sec)

    async def pop(self, jti: str) -> Optional[str]:
        item = self._data.pop(jti, None)
        if not item:
            return None
        user_id, exp = item
        if time.time() > exp:
            return None
        return user_id

    async def revoke(self, jti: str) -> None:
        self._data.pop(jti, None)


class RedisRefreshStore(RefreshStore):
    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as redis

        self._r = redis.from_url(redis_url, decode_responses=True)

    def _key(self, jti: str) -> str:
        return f"scanlead:refresh:{jti}"

    async def put(self, jti: str, user_id: str, ttl_sec: int) -> None:
        await self._r.setex(self._key(jti), ttl_sec, user_id)

    async def pop(self, jti: str) -> Optional[str]:
        key = self._key(jti)
        user_id = await self._r.get(key)
        if user_id:
            await self._r.delete(key)
        return user_id

    async def revoke(self, jti: str) -> None:
        await self._r.delete(self._key(jti))


def build_refresh_store(redis_url: Optional[str]) -> RefreshStore:
    if redis_url:
        try:
            return RedisRefreshStore(redis_url)
        except Exception:
            return MemoryRefreshStore()
    return MemoryRefreshStore()
