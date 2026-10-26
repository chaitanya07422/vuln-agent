from __future__ import annotations

from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import looks_like_html_document
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Fingerprint / header gated. Detect-only: Spring actuator one-shots.


class SpringJavaAgent(BaseAgent):
    name = "spring_java"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=20_000)
        headers = {k.lower(): v for k, v in ((home.get("headers") or {}) if home.get("ok") else {}).items()}
        powered = (headers.get("x-powered-by") or "") + (headers.get("server") or "")
        body = (home.get("body") or "") if home.get("ok") else ""
        looks = any(
            x in (powered + body).lower()
            for x in ("spring", "tomcat", "whitelabel error", "javax.servlet", "actuator")
        )
        # Always try a couple of actuator paths — cheap; idle cleanly if 404 HTML SPA
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        paths = [
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/mappings",
            "/actuator/beans",
            "/actuator/configprops",
            "/manage/health",
            "/jolokia",
        ]
        hits = []
        for path in paths:
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=30_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            b = resp.get("body") or ""
            h = resp.get("headers") or {}
            if code != 200:
                continue
            if looks_like_html_document(b, h):
                continue
            if not (b.strip().startswith("{") or b.strip().startswith("[")):
                continue
            hits.append(path)
            sev = "high" if path in ("/actuator/env", "/actuator/beans", "/actuator/configprops", "/jolokia") else "medium"
            if path.endswith("/health") or path == "/actuator":
                sev = "low"
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=f"Spring actuator endpoint exposed: {path}",
                    evidence_url=target,
                    evidence_snippet=b[:180],
                    fix="Disable unused actuators; require auth/network policy for /actuator/*.",
                    tags=["spring", "actuator"],
                )
            )

        if not looks and not hits:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["spring_java"] = {"skipped": True}
            return

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["spring_java"] = {"hits": hits}
