from __future__ import annotations

import asyncio
from copy import deepcopy
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
