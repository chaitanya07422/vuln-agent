from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

KEY_PREFIX = "sl_live_"
MAX_KEYS_PER_USER = 5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_api_key() -> Tuple[str, str, str]:
    """Return (raw_key, key_id, key_hash). Raw is shown once."""
    secret = secrets.token_urlsafe(32)
    raw = f"{KEY_PREFIX}{secret}"
    key_id = raw[:16]
    return raw, key_id, hash_api_key(raw)


def looks_like_api_key(token: str) -> bool:
    return bool(token) and token.startswith(KEY_PREFIX) and len(token) > len(KEY_PREFIX) + 8


def public_key_meta(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": entry.get("id"),
        "prefix": entry.get("prefix") or entry.get("key_id") or "",
        "name": entry.get("name") or "",
        "created_at": entry.get("created_at"),
        "last_used_at": entry.get("last_used_at"),
    }


def find_key_entry(user: Dict[str, Any], key_id: str) -> Optional[Dict[str, Any]]:
    for entry in user.get("api_keys") or []:
        if entry.get("id") == key_id:
            return entry
    return None


def verify_user_api_key(user: Dict[str, Any], raw: str) -> Optional[Dict[str, Any]]:
    digest = hash_api_key(raw)
    for entry in user.get("api_keys") or []:
        stored = entry.get("hash") or ""
        if stored and hmac.compare_digest(stored, digest):
            return entry
    return None


def append_api_key(
    user: Dict[str, Any],
    *,
    name: str = "",
) -> Tuple[Dict[str, Any], str]:
    """Add a new key to user dict; returns (updated_user_fields_api_keys, raw_key)."""
    keys: List[Dict[str, Any]] = list(user.get("api_keys") or [])
    if len(keys) >= MAX_KEYS_PER_USER:
        raise ValueError(f"At most {MAX_KEYS_PER_USER} API keys per account")
    raw, key_id, key_hash = generate_api_key()
    entry = {
        "id": secrets.token_hex(8),
        "prefix": key_id,
        "hash": key_hash,
        "name": (name or "").strip()[:64],
        "created_at": _utc_now(),
        "last_used_at": None,
    }
    keys.append(entry)
    return keys, raw


def remove_api_key(user: Dict[str, Any], key_id: str) -> List[Dict[str, Any]]:
    keys = list(user.get("api_keys") or [])
    next_keys = [k for k in keys if k.get("id") != key_id]
    if len(next_keys) == len(keys):
        raise KeyError(key_id)
    return next_keys


def touch_api_key(keys: List[Dict[str, Any]], key_id: str) -> List[Dict[str, Any]]:
    out = []
    now = _utc_now()
    for entry in keys:
        row = dict(entry)
        if row.get("id") == key_id:
            row["last_used_at"] = now
        out.append(row)
    return out
