from __future__ import annotations

from typing import Optional, Tuple

from vuln_agent.auth.quotas import GUEST_LIFETIME_LIMIT


class GuestQuotaStore:
    """Lifetime guest scan counters (cookie id + optional IP)."""

    async def get_count(self, guest_id: str) -> int:
        raise NotImplementedError

    async def incr(self, guest_id: str) -> int:
        raise NotImplementedError

    async def get_ip_count(self, ip: str) -> int:
        raise NotImplementedError

    async def incr_ip(self, ip: str) -> int:
        raise NotImplementedError

    async def effective_used(self, guest_id: str, ip: Optional[str]) -> int:
        gid_n = await self.get_count(guest_id) if guest_id else 0
        ip_n = await self.get_ip_count(ip) if ip else 0
        return max(gid_n, ip_n)

    async def consume(self, guest_id: str, ip: Optional[str]) -> Tuple[int, int]:
        """Increment counters; return (used_after, limit)."""
        used = await self.incr(guest_id)
        if ip:
            ip_used = await self.incr_ip(ip)
            used = max(used, ip_used)
        return used, GUEST_LIFETIME_LIMIT


class MemoryGuestQuotaStore(GuestQuotaStore):
    def __init__(self) -> None:
        self._by_id: dict[str, int] = {}
        self._by_ip: dict[str, int] = {}

    async def get_count(self, guest_id: str) -> int:
        return int(self._by_id.get(guest_id) or 0)

    async def incr(self, guest_id: str) -> int:
        self._by_id[guest_id] = int(self._by_id.get(guest_id) or 0) + 1
        return self._by_id[guest_id]

    async def get_ip_count(self, ip: str) -> int:
        return int(self._by_ip.get(ip) or 0)

    async def incr_ip(self, ip: str) -> int:
        self._by_ip[ip] = int(self._by_ip.get(ip) or 0) + 1
        return self._by_ip[ip]


class RedisGuestQuotaStore(GuestQuotaStore):
    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as redis

        self._r = redis.from_url(redis_url, decode_responses=True)

    def _id_key(self, guest_id: str) -> str:
        return f"scanlead:guest:id:{guest_id}"

    def _ip_key(self, ip: str) -> str:
        return f"scanlead:guest:ip:{ip}"

    async def get_count(self, guest_id: str) -> int:
        v = await self._r.get(self._id_key(guest_id))
        return int(v or 0)

    async def incr(self, guest_id: str) -> int:
        # Lifetime — no TTL expiry (product: never refill)
        return int(await self._r.incr(self._id_key(guest_id)))

    async def get_ip_count(self, ip: str) -> int:
        v = await self._r.get(self._ip_key(ip))
        return int(v or 0)

    async def incr_ip(self, ip: str) -> int:
        return int(await self._r.incr(self._ip_key(ip)))


def build_guest_quota_store(redis_url: Optional[str]) -> GuestQuotaStore:
    if redis_url:
        try:
            return RedisGuestQuotaStore(redis_url)
        except Exception:
            return MemoryGuestQuotaStore()
    return MemoryGuestQuotaStore()
