from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from vuln_agent.core.errors import ScanNotFoundError


class MemoryScanStore:
    """In-memory scan store for local/dev. Swap for Mongo later without changing Lead."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._scans: Dict[str, Dict[str, Any]] = {}

    async def create(self, record: Dict[str, Any]) -> Dict[str, Any]:
        async with self._lock:
            self._scans[record["id"]] = deepcopy(record)
            return deepcopy(record)

    async def get(self, scan_id: str) -> Dict[str, Any]:
        async with self._lock:
            if scan_id not in self._scans:
                raise ScanNotFoundError(scan_id)
            return deepcopy(self._scans[scan_id])

    async def update(self, scan_id: str, **fields: Any) -> Dict[str, Any]:
        async with self._lock:
            if scan_id not in self._scans:
                raise ScanNotFoundError(scan_id)
            self._scans[scan_id].update(fields)
            return deepcopy(self._scans[scan_id])

    async def list(self, limit: int = 50) -> list:
        async with self._lock:
            items = list(self._scans.values())
            items.sort(key=lambda s: s.get("created_at") or "", reverse=True)
            return [deepcopy(s) for s in items[:limit]]

    async def list_by_owner(self, owner_id: str, limit: int = 50) -> list:
        async with self._lock:
            items = [s for s in self._scans.values() if s.get("owner_id") == owner_id]
            items.sort(key=lambda s: s.get("created_at") or "", reverse=True)
            return [deepcopy(s) for s in items[:limit]]

    async def count_by_owner(self, owner_id: str, *, source: Optional[str] = None) -> int:
        async with self._lock:
            n = 0
            for s in self._scans.values():
                if s.get("owner_id") != owner_id:
                    continue
                if source is None:
                    n += 1
                    continue
                # Untagged legacy rows count as web
                row_source = s.get("source") or "web"
                if row_source == source:
                    n += 1
            return n

    async def fail_stale_running(self, older_than_sec: float = 960.0) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=older_than_sec)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        n = 0
        async with self._lock:
            for scan in self._scans.values():
                if scan.get("status") not in ("queued", "running"):
                    continue
                if (scan.get("created_at") or "") >= cutoff:
                    continue
                scan["status"] = "failed"
                scan["finished_at"] = now
                scan["error"] = "TimeoutError: stale scan sweeper (worker orphan)"
                n += 1
        return n
