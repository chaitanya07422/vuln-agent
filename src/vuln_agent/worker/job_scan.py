from __future__ import annotations

from arq.connections import RedisSettings

from vuln_agent.core.context import Scope
from vuln_agent.core.lead import LeadRunner
from vuln_agent.llm.factory import build_llm_router
from vuln_agent.playbook_loader import default_playbook_store
from vuln_agent.settings import Settings
from vuln_agent.store.mongo import build_store


async def run_scan_job(ctx, scan_id: str, url: str, host: str, scheme: str) -> None:
    """ARQ job: rebuild LeadRunner with shared Mongo store and run the scan."""
    settings = Settings.load()
    store = build_store(settings.mongo_uri)
    playbooks = default_playbook_store(settings.config)
    llm = build_llm_router(settings.llm)
    lead = LeadRunner(settings, store, playbooks=playbooks, llm=llm)
    scope = Scope(host=host, scheme=scheme, allow_hosts=[host])
    await lead.run_scan(scan_id, url, scope)


def _redis_settings() -> RedisSettings:
    settings = Settings.load()
    if settings.redis_url:
        return RedisSettings.from_dsn(settings.redis_url)
    return RedisSettings(host="localhost", port=6379)


class WorkerSettings:
    functions = [run_scan_job]
    redis_settings = _redis_settings()
    max_jobs = 10
