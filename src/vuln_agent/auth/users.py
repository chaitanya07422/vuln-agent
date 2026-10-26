from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserStore:
    """Mongo or memory users collection."""

    async def upsert_google(
        self,
        *,
        google_id: str,
        email: str,
        name: str,
        picture: str | None = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def update(self, user_id: str, **fields: Any) -> Dict[str, Any]:
        raise NotImplementedError


class MemoryUserStore(UserStore):
    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}
        self._by_google: Dict[str, str] = {}
        self._by_email: Dict[str, str] = {}

    async def upsert_google(
        self,
        *,
        google_id: str,
        email: str,
        name: str,
        picture: str | None = None,
    ) -> Dict[str, Any]:
        email_l = email.lower().strip()
        if google_id in self._by_google:
            uid = self._by_google[google_id]
            user = self._users[uid]
            user.update({"email": email_l, "name": name, "picture": picture})
            return deepcopy(user)
        if email_l in self._by_email:
            uid = self._by_email[email_l]
            user = self._users[uid]
            user["google_id"] = google_id
            user["name"] = name or user.get("name")
            user["picture"] = picture or user.get("picture")
            self._by_google[google_id] = uid
            return deepcopy(user)
        uid = str(uuid4())
        user = {
            "id": uid,
            "email": email_l,
            "name": name,
            "picture": picture,
            "google_id": google_id,
            "plan": "free",
            "plan_expires_at": None,
            "created_at": _utc_now(),
        }
        self._users[uid] = user
        self._by_google[google_id] = uid
        self._by_email[email_l] = uid
        return deepcopy(user)

    async def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        u = self._users.get(user_id)
        return deepcopy(u) if u else None

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        uid = self._by_email.get(email.lower().strip())
        return await self.get(uid) if uid else None

    async def update(self, user_id: str, **fields: Any) -> Dict[str, Any]:
        if user_id not in self._users:
            raise KeyError(user_id)
        self._users[user_id].update(fields)
        return deepcopy(self._users[user_id])


class MongoUserStore(UserStore):
    def __init__(self, uri: str, db_name: str = "vuln_agent") -> None:
        from motor.motor_asyncio import AsyncIOMotorClient

        self._col = AsyncIOMotorClient(uri)[db_name]["users"]

    async def upsert_google(
        self,
        *,
        google_id: str,
        email: str,
        name: str,
        picture: str | None = None,
    ) -> Dict[str, Any]:
        email_l = email.lower().strip()
        existing = await self._col.find_one({"google_id": google_id})
        if not existing:
            existing = await self._col.find_one({"email": email_l})
        if existing:
            await self._col.update_one(
                {"_id": existing["_id"]},
                {
                    "$set": {
                        "google_id": google_id,
                        "email": email_l,
                        "name": name,
                        "picture": picture,
                    }
                },
            )
            doc = await self._col.find_one({"_id": existing["_id"]}, {"_id": 0})
            return doc or {}
        uid = str(uuid4())
        doc = {
            "_id": uid,
            "id": uid,
            "email": email_l,
            "name": name,
            "picture": picture,
            "google_id": google_id,
            "plan": "free",
            "plan_expires_at": None,
            "created_at": _utc_now(),
        }
        await self._col.insert_one(doc)
        doc.pop("_id", None)
        return doc

    async def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        return await self._col.find_one({"id": user_id}, {"_id": 0})

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return await self._col.find_one({"email": email.lower().strip()}, {"_id": 0})

    async def update(self, user_id: str, **fields: Any) -> Dict[str, Any]:
        from pymongo import ReturnDocument

        res = await self._col.find_one_and_update(
            {"id": user_id},
            {"$set": fields},
            return_document=ReturnDocument.AFTER,
            projection={"_id": 0},
        )
        if not res:
            raise KeyError(user_id)
        return res


def build_user_store(mongo_uri: Optional[str]) -> UserStore:
    if mongo_uri:
        try:
            return MongoUserStore(mongo_uri)
        except Exception:
            return MemoryUserStore()
    return MemoryUserStore()
