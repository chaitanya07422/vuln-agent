import pytest

from vuln_agent.core.context import Scope
from vuln_agent.core.lead import LeadRunner
from vuln_agent.settings import Settings
from vuln_agent.store.memory import MemoryScanStore


@pytest.mark.asyncio
async def test_enqueue_falls_back_in_process(monkeypatch):
    store = MemoryScanStore()
    settings = Settings(enabled_agents=["recon"], redis_url=None, mongo_uri=None)
    lead = LeadRunner(settings, store)

    called = {"n": 0}

    async def fake_run(scan_id, url, scope):
        called["n"] += 1
        await store.update(scan_id, status="done")

    monkeypatch.setattr(lead, "run_scan", fake_run)
    rec = await lead.start_scan(url="https://example.com", attested=True)
    # give create_task a tick
    import asyncio

    await asyncio.sleep(0.05)
    assert called["n"] == 1
    assert rec["status"] == "queued"
