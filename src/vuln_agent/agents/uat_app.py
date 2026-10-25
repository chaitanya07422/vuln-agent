from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding


class UatAppAgent(BaseAgent):
    name = "uat_app"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        # Fetch homepage once and extract staging-like links
        resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return
        body = resp.get("body") or ""
        hrefs = re.findall(r"""href=["']([^"']+)["']""", body, flags=re.I)
        patterns = ("uat.", "staging.", "stage.", "dev.", "test.", "-uat", "-staging")
        seen = set()
        for href in hrefs:
            full = urljoin(ctx.url, href)
            host = (urlparse(full).hostname or "").lower()
            if not host or host in seen:
                continue
            if not any(p in host for p in patterns):
                continue
            # same registrable-ish: share suffix with primary host
            primary = ctx.scope.host
            if primary not in host and not host.endswith("." + primary.split(".", 1)[-1]):
                # still report if linked; one GET only if host shares parent domain label
                parent = ".".join(primary.split(".")[-2:]) if "." in primary else primary
                if parent not in host:
                    continue
            seen.add(host)
            probe = await ctx.tools.http_request(method="GET", url=f"{urlparse(full).scheme}://{host}/")
            await ctx.audit_event(agent=self.name, tool="http_request", url=host, ok=probe.get("ok"))
            if probe.get("ok"):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"Staging/UAT host reachable: {host}",
                        evidence_url=probe.get("url"),
                        evidence_snippet=f"Linked from production; HTTP {probe.get('status_code')}",
                        fix="Remove staging links from production or lock staging behind auth/VPN.",
                        tags=["uat", "staging"],
                    )
                )
            if len(seen) >= 3:
                break
