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
        ctx.fingerprint = fp

        status = resp.get("status_code")
        await ctx.emit_finding(
            Finding(
                agent=self.name,
                severity="info",
                title=f"Recon complete — HTTP {status}",
                evidence_url=resp.get("url") or ctx.url,
                evidence_snippet=(
                    f"tags={fp.get('tags')}; server={fp.get('server')}; "
                    f"title={fp.get('title')!r}"
                ),
                tags=["recon", *list(fp.get("tags") or [])],
            )
        )

        if fp.get("server"):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Server header exposed: {fp['server']}",
                    evidence_url=resp.get("url") or ctx.url,
                    evidence_snippet=f"Server: {fp['server']}",
                    fix="Omit or genericize the Server header where possible.",
                    tags=["recon", "header"],
                )
            )

        tags = list(fp.get("tags") or [])
        if tags and tags != ["unknown"]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Tech fingerprint: {', '.join(tags)}",
                    evidence_url=resp.get("url") or ctx.url,
                    evidence_snippet=f"Detected tags: {tags}",
                    tags=["recon", "fingerprint", *tags],
                )
            )
        elif "unknown" in tags:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="Unknown stack — adapt probes recommended",
                    evidence_url=resp.get("url") or ctx.url,
                    evidence_snippet="No known CMS/framework markers matched.",
                    tags=["recon", "unknown"],
                )
            )
