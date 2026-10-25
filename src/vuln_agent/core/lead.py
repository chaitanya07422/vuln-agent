from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vuln_agent.core.context import ScanContext, Scope
from vuln_agent.core.finding import Finding
from vuln_agent.core.registry import load_agents
from vuln_agent.settings import Settings
from vuln_agent.tools.http import HttpRequestTool, ToolBus


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def render_markdown(scan: Dict[str, Any]) -> str:
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
        f"```json\n{scan.get('fingerprint')}\n```",
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
            if f.get("fix"):
                lines.extend([f"**Fix:** {f['fix']}", ""])
    return "\n".join(lines)


class LeadRunner:
    def __init__(self, settings: Settings, store: Any) -> None:
        self.settings = settings
        self.store = store

    def _tools(self) -> ToolBus:
        http = HttpRequestTool(
            timeout_sec=self.settings.limits.request_timeout_sec,
            user_agent=self.settings.http.user_agent,
            follow_redirects=self.settings.http.follow_redirects,
            max_redirects=self.settings.http.max_redirects,
        )
        return ToolBus(http)

    async def start_scan(self, *, url: str, attested: bool) -> Dict[str, Any]:
        if not attested:
            raise ValueError("attestation required")
        scope = Scope.from_url(url)
        scan_id = str(uuid4())
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
        }
        await self.store.create(record)
        asyncio.create_task(self._run(scan_id, url, scope))
        return record

    async def _run(self, scan_id: str, url: str, scope: Scope) -> None:
        await self.store.update(scan_id, status="running")
        tools = self._tools()
        ctx = ScanContext(scan_id=scan_id, url=url, scope=scope, tools=tools)

        try:
            agents = load_agents(self.settings.enabled_agents)
            # recon barrier first
            recon = [a for a in agents if a.name == "recon"]
            others = [a for a in agents if a.name != "recon"]

            for agent in recon:
                await agent.run(ctx)

            tags = set((ctx.fingerprint or {}).get("tags") or [])

            async def _maybe_run(agent) -> None:
                if agent.requires_tags and not set(agent.requires_tags).issubset(tags):
                    return
                if agent.skip_if_tags and set(agent.skip_if_tags) & tags:
                    return
                await agent.run(ctx)

            if others:
                await asyncio.wait_for(
                    asyncio.gather(*[_maybe_run(a) for a in others]),
                    timeout=self.settings.limits.scan_timeout_sec,
                )

            findings = [f.model_dump() if isinstance(f, Finding) else f for f in ctx.findings]
            report = {
                "id": scan_id,
                "url": url,
                "status": "done",
                "created_at": (await self.store.get(scan_id))["created_at"],
                "finished_at": _utc_now(),
                "fingerprint": ctx.fingerprint,
                "findings": findings,
            }
            md = render_markdown(report)
            await self.store.update(
                scan_id,
                status="done",
                finished_at=report["finished_at"],
                fingerprint=ctx.fingerprint,
                findings=findings,
                audit=ctx.audit,
                report_md=md,
            )
        except Exception as exc:  # noqa: BLE001 — surface to scan record
            await self.store.update(
                scan_id,
                status="failed",
                finished_at=_utc_now(),
                error=f"{type(exc).__name__}: {exc}",
                fingerprint=ctx.fingerprint,
                findings=[f.model_dump() for f in ctx.findings],
                audit=ctx.audit,
            )
