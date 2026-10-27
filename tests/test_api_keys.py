import asyncio

from vuln_agent.auth.api_keys import (
    append_api_key,
    hash_api_key,
    looks_like_api_key,
    remove_api_key,
    verify_user_api_key,
)
from vuln_agent.auth.users import MemoryUserStore


def test_generate_and_verify():
    user = {"id": "u1", "api_keys": []}
    keys, raw = append_api_key(user, name="mcp")
    assert looks_like_api_key(raw)
    assert raw.startswith("sl_live_")
    user["api_keys"] = keys
    entry = verify_user_api_key(user, raw)
    assert entry is not None
    assert entry["name"] == "mcp"
    assert entry["hash"] == hash_api_key(raw)
    assert verify_user_api_key(user, raw + "x") is None


def test_max_keys():
    user = {"id": "u1", "api_keys": []}
    for i in range(5):
        keys, _ = append_api_key(user, name=str(i))
        user["api_keys"] = keys
    try:
        append_api_key(user, name="overflow")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_memory_store_lookup():
    async def _run():
        store = MemoryUserStore()
        user = await store.upsert_google(
            google_id="g1", email="a@b.com", name="A", picture=None
        )
        await store.update(user["id"], plan="pro")
        user = await store.get(user["id"])
        keys, raw = append_api_key(user or {}, name="cli")
        await store.update(user["id"], api_keys=keys)
        found = await store.find_by_api_key_hash(hash_api_key(raw))
        assert found is not None
        assert found["id"] == user["id"]
        next_keys = remove_api_key(found, keys[0]["id"])
        await store.update(user["id"], api_keys=next_keys)
        assert await store.find_by_api_key_hash(hash_api_key(raw)) is None

    asyncio.run(_run())
