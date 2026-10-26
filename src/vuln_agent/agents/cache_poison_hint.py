from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: unkeyed header reflection (Host / X-Forwarded-*). No poison delivery.


class CachePoisonHintAgent(BaseAgent):
    name = "cache_poison_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        marker = f"scanlead-cph-{ctx.scan_id[:8] if ctx.scan_id else 'x'}.invalid"
        probes = [
            {"X-Forwarded-Host": marker},
            {"X-Forwarded-Scheme": "nothttps"},
            {"X-Original-URL": "/scanlead-poison-check"},
            {"X-Rewrite-URL": "/scanlead-poison-check"},
        ]
        hits = []
        for headers in probes:
            resp = await ctx.tools.http_request(
                method="GET",
                url=ctx.url,
                headers=headers,
                max_body_bytes=30_000,
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            body = resp.get("body") or ""
            resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            blob = body + " " + " ".join(resp_headers.values())
            key = next(iter(headers))
            if marker in blob or "scanlead-poison-check" in blob or marker in (resp.get("url") or ""):
                hits.append(key)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"Unkeyed header reflection: {key}",
                        evidence_url=ctx.url,
                        evidence_snippet=f"{key} value reflected in response",
                        fix="Do not trust X-Forwarded-* / Host overrides from clients; configure trusted proxy hops only.",
                        tags=["cache", "headers"],
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cache_poison_hint"] = {"hits": hits}
