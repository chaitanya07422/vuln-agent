from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.fingerprint import fingerprint


class ReconAgent(BaseAgent):
    name = "recon"
    requires_tags: list[str] = []
    skip_if_tags: list[str] = []

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", result_ok=resp.get("ok"), url=ctx.url)

        if not resp.get("ok"):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="Target unreachable during recon",
                    evidence_url=ctx.url,
                    evidence_snippet=f"{resp.get('error')}: {resp.get('detail')}",
                    fix="Confirm the URL is reachable over the public internet and allows outbound scans.",
                    tags=["recon", "unreachable"],
                )
            )
            ctx.fingerprint = {"tags": ["unreachable"], "server": None, "powered_by": None, "title": None}
            return

        headers = resp.get("headers") or {}
        body = resp.get("body") or ""
        fp = fingerprint(headers, body)
        # Fingerprint feeds the summary — no info finding cards for routine recon
        ctx.fingerprint = fp
        await ctx.audit_event(
            agent=self.name,
            tool="fingerprint",
            tags=fp.get("tags"),
            server=fp.get("server"),
            title=fp.get("title"),
        )
