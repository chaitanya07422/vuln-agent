from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from vuln_agent.core.context import ScanContext, Scope
from vuln_agent.core.finding import Finding
from vuln_agent.core.progress import initial_agents_progress, set_agent_status
from vuln_agent.core.registry import load_agents
from vuln_agent.llm.router import LLMRouter
from vuln_agent.playbook_loader import PlaybookStore, default_playbook_store
from vuln_agent.settings import Settings
from vuln_agent.tools.http import HttpRequestTool, ToolBus
from vuln_agent.tools.rate_limit import AsyncRateLimiter


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def render_markdown(scan: Dict[str, Any]) -> str:
    if scan.get("report_md"):
        return scan["report_md"]
    lines = [
        f"# Scan report — {scan.get('url')}",
        "",
        f"- **scan_id:** `{scan.get('id')}`",
        f"- **status:** {scan.get('status')}",
        f"- **started:** {scan.get('created_at')}",
        f"- **finished:** {scan.get('finished_at') or '—'}",
        "",
        "## Fingerprint",
        "",
        f"```json\n{json.dumps(scan.get('fingerprint') or {}, indent=2)}\n```",
        "",
        "## Findings",
        "",
    ]
    findings: List[Dict[str, Any]] = scan.get("findings") or []
    if not findings:
        lines.append("_No findings._")
    else:
        for i, f in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {i}. [{f.get('severity', '').upper()}] {f.get('title')}",
                    "",
                    f"- **agent:** {f.get('agent')}",
                    f"- **url:** {f.get('evidence_url') or '—'}",
                    f"- **tags:** {', '.join(f.get('tags') or []) or '—'}",
                    "",
                    "```",
                    str(f.get("evidence_snippet") or ""),
                    "```",
                    "",
                ]
            )
            if f.get("explanation"):
                lines.extend([f"**Why it matters:** {f['explanation']}", ""])
            if f.get("fix"):
                lines.extend([f"**Fix:** {f['fix']}", ""])
    return "\n".join(lines)


class LeadRunner:
    def __init__(
        self,
        settings: Settings,
        store: Any,
        playbooks: PlaybookStore | None = None,
        llm: LLMRouter | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.playbooks = playbooks or default_playbook_store(settings.config)
        self.llm = llm or LLMRouter()

    def _tools(self, allow_hosts: list | None = None) -> ToolBus:
        limiter = AsyncRateLimiter(self.settings.limits.max_rps)
        http = HttpRequestTool(
            timeout_sec=self.settings.limits.request_timeout_sec,
            user_agent=self.settings.http.user_agent,
            follow_redirects=self.settings.http.follow_redirects,
            max_redirects=self.settings.http.max_redirects,
            rate_limiter=limiter,
            allow_hosts=allow_hosts,
            enforce_ssrf=True,
        )
        return ToolBus(http)

    async def start_scan(
        self,
        *,
        url: str,
        attested: bool,
        owner_id: str | None = None,
        parent_scan_id: str | None = None,
    ) -> Dict[str, Any]:
        if not attested:
            raise ValueError("attestation required")
        scope = Scope.from_url(url)
        scan_id = str(uuid4())
        progress = initial_agents_progress(self.settings.enabled_agents)
        import secrets

        claim_token = secrets.token_urlsafe(18)
        record = {
            "id": scan_id,
            "url": url,
            "host": scope.host,
            "status": "queued",
            "created_at": _utc_now(),
            "finished_at": None,
            "fingerprint": {},
            "findings": [],
            "audit": [],
            "error": None,
            "report_md": None,
            "risk_path": None,
            "summary": None,
            "agents_progress": progress,
            "owner_id": owner_id,
            "claim_token": claim_token,
            "parent_scan_id": parent_scan_id,
        }
        await self.store.create(record)
        await self._enqueue(scan_id, url, scope)
        return record

    async def _enqueue(self, scan_id: str, url: str, scope: Scope) -> None:
        redis_url = getattr(self.settings, "redis_url", None)
        mongo_uri = getattr(self.settings, "mongo_uri", None)
        # Cross-process workers need a shared store (Mongo). Otherwise run in-process.
        if redis_url and mongo_uri:
            try:
                from arq import create_pool
                from arq.connections import RedisSettings

                redis = await create_pool(RedisSettings.from_dsn(redis_url))
                await redis.enqueue_job("run_scan_job", scan_id, url, scope.host, scope.scheme)
                await redis.close()
                return
            except Exception:
                # Fall through to in-process if enqueue fails
                pass
        asyncio.create_task(self.run_scan(scan_id, url, scope))

    async def run_scan(self, scan_id: str, url: str, scope: Scope) -> None:
        progress = initial_agents_progress(self.settings.enabled_agents)
        progress_lock = asyncio.Lock()
        await self.store.update(scan_id, status="running", agents_progress=progress)
        tools = self._tools(allow_hosts=list(scope.allow_hosts))
        ctx = ScanContext(
            scan_id=scan_id,
            url=url,
            scope=scope,
            tools=tools,
            playbooks=self.playbooks,
            llm=self.llm,
        )

        async def _mark(agent_name: str, status: str) -> None:
            nonlocal progress
            async with progress_lock:
                progress = set_agent_status(progress, agent_name, status)
                snapshot = [dict(row) for row in progress]
            await self.store.update(scan_id, agents_progress=snapshot)

        try:
            agents = load_agents(self.settings.enabled_agents)
            recon = [a for a in agents if a.name == "recon"]
            reporter = [a for a in agents if a.name == "reporter"]
            # js_audit first (fills fingerprint.js_api_paths); adapt last (uses them)
            js_audit = [a for a in agents if a.name == "js_audit"]
            adapt = [a for a in agents if a.name == "adapt"]
            mid = [a for a in agents if a.name not in ("recon", "reporter", "js_audit", "adapt")]

            async def _maybe_run(agent) -> None:
                tags_now = set((ctx.fingerprint or {}).get("tags") or [])
                if agent.requires_tags and not set(agent.requires_tags).issubset(tags_now):
                    await _mark(agent.name, "skipped")
                    return
                if agent.skip_if_tags and set(agent.skip_if_tags) & tags_now:
                    await _mark(agent.name, "skipped")
                    return
                await _mark(agent.name, "running")
                try:
                    await agent.run(ctx)
                except Exception:
                    await _mark(agent.name, "failed")
                    raise
                await _mark(agent.name, "done")

            for agent in recon:
                await _maybe_run(agent)

            for agent in js_audit:
                await _maybe_run(agent)

            if mid:
                await asyncio.wait_for(
                    asyncio.gather(*[_maybe_run(a) for a in mid]),
                    timeout=self.settings.limits.scan_timeout_sec,
                )

            for agent in adapt:
                await _maybe_run(agent)

            for agent in reporter:
                await _maybe_run(agent)

            # Snapshot LLM token usage into fingerprint for UI / billing insight
            if ctx.llm and hasattr(ctx.llm, "usage_summary"):
                try:
                    ctx.fingerprint = dict(ctx.fingerprint or {})
                    ctx.fingerprint["llm_usage"] = ctx.llm.usage_summary()
                except Exception:
                    pass

            findings = [f.model_dump() if isinstance(f, Finding) else f for f in ctx.findings]
            md = ctx.report_md or render_markdown(
                {
                    "id": scan_id,
                    "url": url,
                    "status": "done",
                    "created_at": (await self.store.get(scan_id))["created_at"],
                    "finished_at": _utc_now(),
                    "fingerprint": ctx.fingerprint,
                    "findings": findings,
                }
            )
            await self.store.update(
                scan_id,
                status="done",
                finished_at=_utc_now(),
                fingerprint=ctx.fingerprint,
                findings=findings,
                audit=ctx.audit,
                report_md=md,
                risk_path=ctx.risk_path,
                summary=ctx.summary,
                agents_progress=progress,
            )
        except asyncio.CancelledError:
            # ARQ/job cancel — must persist failed or UI stays on "running" forever.
            await self.store.update(
                scan_id,
                status="failed",
                finished_at=_utc_now(),
                error="CancelledError: job cancelled or timed out",
                fingerprint=ctx.fingerprint,
                findings=[f.model_dump() for f in ctx.findings],
                audit=ctx.audit,
                agents_progress=progress,
            )
            raise
        except Exception as exc:  # noqa: BLE001
            await self.store.update(
                scan_id,
                status="failed",
                finished_at=_utc_now(),
                error=f"{type(exc).__name__}: {exc}",
                fingerprint=ctx.fingerprint,
                findings=[f.model_dump() for f in ctx.findings],
                audit=ctx.audit,
                agents_progress=progress,
            )
