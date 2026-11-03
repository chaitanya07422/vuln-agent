from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Optional


class SecurityService:
    """Redis-backed IP blocks and MongoDB request audit events."""

    def __init__(self, mongo_uri: Optional[str], redis_url: Optional[str]) -> None:
        self._events = None
        self._redis = None
        self._memory_blocks: set[str] = set()
        if mongo_uri:
            try:
                from motor.motor_asyncio import AsyncIOMotorClient
                self._mongo_client = AsyncIOMotorClient(mongo_uri)
                self._events = self._mongo_client["vuln_agent"]["security_events"]
            except Exception:
                self._events = None
        if redis_url:
            try:
                import redis.asyncio as redis
                self._redis = redis.from_url(redis_url, decode_responses=True)
            except Exception:
                self._redis = None

    @staticmethod
    def normalize_ip(value: str) -> str:
        return str(ip_address(value.strip()))

    async def is_blocked(self, ip: str) -> bool:
        key = f"scanlead:security:blocked:{ip}"
        if self._redis is not None:
            try:
                return bool(await self._redis.exists(key))
            except Exception:
                pass
        return ip in self._memory_blocks

    async def block(self, ip: str, reason: str = "manual", ttl_seconds: int = 0) -> None:
        ip = self.normalize_ip(ip)
        key = f"scanlead:security:blocked:{ip}"
        if self._redis is not None:
            try:
                if ttl_seconds > 0:
                    await self._redis.set(key, reason[:200], ex=ttl_seconds)
                else:
                    await self._redis.set(key, reason[:200])
                return
            except Exception:
                pass
        self._memory_blocks.add(ip)

    async def unblock(self, ip: str) -> None:
        ip = self.normalize_ip(ip)
        if self._redis is not None:
            try:
                await self._redis.delete(f"scanlead:security:blocked:{ip}")
            except Exception:
                pass
        self._memory_blocks.discard(ip)

    async def list_blocked(self) -> list[dict[str, Any]]:
        if self._redis is None:
            return [{"ip": ip, "storage": "process-memory"} for ip in sorted(self._memory_blocks)]
        try:
            result = []
            async for key in self._redis.scan_iter(match="scanlead:security:blocked:*"):
                ip = key.rsplit(":", 1)[-1]
                result.append({"ip": ip, "ttl_seconds": await self._redis.ttl(key)})
            return result
        except Exception:
            return [{"ip": ip, "storage": "process-memory"} for ip in sorted(self._memory_blocks)]

    async def record(self, event: dict[str, Any]) -> None:
        if self._events is None:
            return
        try:
            await self._events.insert_one({
                **event,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            # Security logging must never take the API down.
            pass

    async def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if self._events is None:
            return []
        cursor = self._events.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
        return [doc async for doc in cursor]
