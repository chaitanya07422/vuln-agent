from __future__ import annotations

from datetime import datetime, timezone

from arq.connections import RedisSettings

from vuln_agent.core.context import Scope
from vuln_agent.core.lead import LeadRunner
from vuln_agent.llm.factory import build_llm_router
from vuln_agent.playbook_loader import default_playbook_store
from vuln_agent.settings import Settings
from vuln_agent.store.mongo import build_store

# Real scans often take 4–6+ min (reporter LLM). ARQ default is 300s.
_JOB_TIMEOUT_SEC = 900
# Sweep orphans a bit after the job timeout so live jobs aren't killed early.
_STALE_AFTER_SEC = float(_JOB_TIMEOUT_SEC + 60)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _sweep_stale(ctx) -> None:
    """On worker boot / before jobs: close orphan running scans left by crashes."""
    try:
        settings = Settings.load()
        store = build_store(settings.mongo_uri)
        n = await store.fail_stale_running(_STALE_AFTER_SEC)
        if n:
            print(f"sweeper: marked {n} stale scan(s) failed", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"sweeper: skipped ({type(exc).__name__}: {exc})", flush=True)


async def run_scan_job(ctx, scan_id: str, url: str, host: str, scheme: str) -> None:
    """ARQ job: rebuild LeadRunner with shared Mongo store and run the scan."""
    settings = Settings.load()
    store = build_store(settings.mongo_uri)
    try:
        await store.fail_stale_running(_STALE_AFTER_SEC)
    except Exception:
        pass
    playbooks = default_playbook_store(settings.config)
    llm = build_llm_router(settings.llm)
    lead = LeadRunner(settings, store, playbooks=playbooks, llm=llm)
    scope = Scope(host=host, scheme=scheme, allow_hosts=[host])
    try:
        await lead.run_scan(scan_id, url, scope)
    except BaseException as exc:
        # ARQ job_timeout cancels with CancelledError (BaseException, not Exception),
        # so LeadRunner's except Exception never marks the scan failed — leave a trail.
        try:
            doc = await store.get(scan_id)
            if doc and doc.get("status") in ("queued", "running"):
                await store.update(
                    scan_id,
                    status="failed",
                    finished_at=_utc_now(),
                    error=f"{type(exc).__name__}: {exc or 'job cancelled or timed out'}",
                )
        except Exception:
            pass
        raise


def _redis_settings() -> RedisSettings:
    settings = Settings.load()
    if settings.redis_url:
        return RedisSettings.from_dsn(settings.redis_url)
    return RedisSettings(host="localhost", port=6379)


class WorkerSettings:
    functions = [run_scan_job]
    redis_settings = _redis_settings()
    max_jobs = 10
    job_timeout = _JOB_TIMEOUT_SEC
    on_startup = [_sweep_stale]
