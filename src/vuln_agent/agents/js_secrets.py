from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.js_discover import script_urls
from vuln_agent.agents.secrets_patterns import scan_secrets
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: regex scan public HTML/JS. No secret validation or abuse.

JS_MAX = 1_500_000


class JsSecretsAgent(BaseAgent):
    name = "js_secrets"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        home = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if not home.get("ok"):
            return

        blobs = [home.get("body") or ""]
        for script in script_urls(home.get("body") or "", ctx.url)[:10]:
            js = await ctx.tools.http_request(method="GET", url=script, max_body_bytes=JS_MAX)
            await ctx.audit_event(agent=self.name, tool="http_request", url=script, ok=js.get("ok"))
            if js.get("ok") and js.get("body"):
                blobs.append(js["body"])

        sample = "\n".join(blobs)[:JS_MAX]
        hits = scan_secrets(sample)
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["js_secrets"] = {"hit_ids": [h["id"] for h in hits]}

        for h in hits:
            if h["severity"] == "info":
                continue
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=h["severity"],  # type: ignore[arg-type]
                    title=h["title"],
                    evidence_url=ctx.url,
                    evidence_snippet=h["snippet"],
                    fix="Remove secrets from frontend bundles; rotate any exposed credentials; use server-side tokens.",
                    tags=["js", "secrets", h["id"]],
                )
            )
