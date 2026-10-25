from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional

from vuln_agent.core.errors import ScanNotFoundError


class MongoScanStore:
    """Mongo-backed scan store. Falls back gracefully if motor unavailable at import."""

    def __init__(self, uri: str, db_name: str = "vuln_agent") -> None:
        from motor.motor_asyncio import AsyncIOMotorClient

        self._client = AsyncIOMotorClient(uri)
        self._col = self._client[db_name]["scans"]

    async def create(self, record: Dict[str, Any]) -> Dict[str, Any]:
        doc = deepcopy(record)
        doc["_id"] = doc["id"]
        await self._col.insert_one(doc)
        return deepcopy(record)

    async def get(self, scan_id: str) -> Dict[str, Any]:
        doc = await self._col.find_one({"_id": scan_id}, {"_id": 0})
        if not doc:
            raise ScanNotFoundError(scan_id)
        return doc

    async def update(self, scan_id: str, **fields: Any) -> Dict[str, Any]:
        res = await self._col.find_one_and_update(
            {"_id": scan_id},
            {"$set": fields},
            return_document=True,
            projection={"_id": 0},
        )
        if not res:
            raise ScanNotFoundError(scan_id)
        return res

    async def list(self, limit: int = 50) -> list:
        cursor = self._col.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
        return [doc async for doc in cursor]


def build_store(mongo_uri: Optional[str]):
    if mongo_uri:
        try:
            return MongoScanStore(mongo_uri)
        except Exception:
            from vuln_agent.store.memory import MemoryScanStore

            return MemoryScanStore()
    from vuln_agent.store.memory import MemoryScanStore

    return MemoryScanStore()
