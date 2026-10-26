from vuln_agent.auth.guest_quota import MemoryGuestQuotaStore
from vuln_agent.auth.quotas import (
    FREE_SCAN_LIMIT,
    GUEST_LIFETIME_LIMIT,
    create_limit,
    history_limit,
    quota_payload,
)


def test_limits():
    assert GUEST_LIFETIME_LIMIT == 2
    assert FREE_SCAN_LIMIT == 5
    assert create_limit(None) == 2
    assert create_limit({"plan": "free"}) == 5
    assert create_limit({"plan": "pro"}) == 500
    assert history_limit({"plan": "free"}) == 5


def test_quota_payload():
    p = quota_payload(mode="guest", limit=2, used=1)
    assert p["remaining"] == 1
    assert p["can_scan"] is True
    p2 = quota_payload(mode="guest", limit=2, used=2)
    assert p2["remaining"] == 0
    assert p2["can_scan"] is False


async def _guest_store():
    store = MemoryGuestQuotaStore()
    used, limit = await store.consume("g1", "1.2.3.4")
    assert used == 1 and limit == 2
    used, _ = await store.consume("g1", "1.2.3.4")
    assert used == 2
    assert await store.effective_used("g1", "1.2.3.4") == 2


def test_guest_store_sync():
    import asyncio

    asyncio.run(_guest_store())
