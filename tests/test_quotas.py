from vuln_agent.auth.guest_quota import MemoryGuestQuotaStore
from vuln_agent.auth.quotas import (
    FREE_FULL_LIMIT,
    FREE_SCAN_LIMIT,
    GUEST_FULL_LIMIT,
    GUEST_LIFETIME_LIMIT,
    create_limit,
    history_limit,
    quota_payload,
)
from vuln_agent.auth.reveal import apply_reveal, choose_detail_level


def test_limits():
    assert GUEST_LIFETIME_LIMIT == 2
    assert GUEST_FULL_LIMIT == 1
    assert FREE_FULL_LIMIT == 2
    assert FREE_SCAN_LIMIT == 10
    assert create_limit(None) == 2
    assert create_limit({"plan": "free"}) == 10
    assert create_limit({"plan": "pro"}) == 500
    assert history_limit({"plan": "free"}) == 10


def test_choose_detail_level():
    assert choose_detail_level(plan="guest", guest_used_before=0) == "full"
    assert choose_detail_level(plan="guest", guest_used_before=1) == "teaser"
    assert choose_detail_level(plan="free", owner_scan_count=0) == "full"
    assert choose_detail_level(plan="free", owner_scan_count=1) == "full"
    assert choose_detail_level(plan="free", owner_scan_count=2) == "teaser"
    assert choose_detail_level(plan="pro", owner_scan_count=99) == "full"


def test_apply_reveal_teaser():
    scan = {
        "id": "x",
        "url": "https://example.com",
        "detail_level": "teaser",
        "findings": [
            {"agent": "a", "severity": "high", "title": "One", "explanation": "x" * 200},
            {"agent": "b", "severity": "medium", "title": "Two"},
            {"agent": "c", "severity": "low", "title": "Three"},
        ],
        "risk_path": "1. bad thing",
        "summary": {"headline": "Issues", "agents": [{"agent": "a"}]},
    }
    out = apply_reveal(scan)
    assert out["detail_level"] == "teaser"
    assert len(out["findings"]) == 1
    assert out["findings"][0]["title"] == "One"
    assert out["hidden_findings"] == 2
    assert out["risk_path"] is None


def test_quota_payload():
    p = quota_payload(mode="guest", limit=2, used=1, full_limit=1, full_used=1)
    assert p["remaining"] == 1
    assert p["can_scan"] is True
    assert p["next_detail"] == "teaser"
    p2 = quota_payload(mode="guest", limit=2, used=2, full_limit=1, full_used=1)
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
