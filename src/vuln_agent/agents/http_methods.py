from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: OPTIONS/TRACE on origin; note dangerous verb allowance. No method abuse beyond probe.


class HttpMethodsAgent(BaseAgent):
    name = "http_methods"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        results = {}
        for method in ("OPTIONS", "TRACE", "TRACK"):
            resp = await ctx.tools.http_request(method=method, url=ctx.url, max_body_bytes=4000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, method=method, ok=resp.get("ok"))
            if not resp.get("ok"):
                results[method] = {"ok": False}
                continue
            code = resp.get("status_code") or 0
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            results[method] = {
                "status": code,
                "allow": headers.get("allow"),
                "acam": headers.get("access-control-allow-methods"),
            }

            if method == "TRACE" and code == 200:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="HTTP TRACE enabled",
                        evidence_url=ctx.url,
                        evidence_snippet=f"TRACE returned {code}",
                        fix="Disable TRACE/TRACK on the origin and edge.",
                        tags=["http", "methods"],
                    )
                )
            if method == "TRACK" and code == 200:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="HTTP TRACK enabled",
                        evidence_url=ctx.url,
                        evidence_snippet=f"TRACK returned {code}",
                        fix="Disable TRACE/TRACK on the origin and edge.",
                        tags=["http", "methods"],
                    )
                )
            if method == "OPTIONS":
                allow = (headers.get("allow") or headers.get("access-control-allow-methods") or "").upper()
                dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow]
                if dangerous:
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="low",
                            title=f"OPTIONS advertises {', '.join(dangerous)}",
                            evidence_url=ctx.url,
                            evidence_snippet=allow[:200],
                            fix="Only advertise methods the resource actually needs; lock down verbs at the gateway.",
                            tags=["http", "methods"],
                        )
                    )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["http_methods"] = results
