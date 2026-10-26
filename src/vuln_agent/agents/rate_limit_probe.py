from __future__ import annotations

import time
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: soft burst (hard cap 5) on login/API; "no throttle" note. No sprays.


class RateLimitProbeAgent(BaseAgent):
    name = "rate_limit_probe"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        paths = ["/login", "/api/login", "/wp-login.php", "/api/auth/callback", "/api/auth/signin"]
        target = None
        for path in paths:
            url = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=url, max_body_bytes=2000)
            if resp.get("ok") and (resp.get("status_code") or 0) not in (404, 410):
                target = url
                break
        if not target:
            target = ctx.url

        statuses = []
        throttled = False
        t0 = time.monotonic()
        for i in range(5):
            resp = await ctx.tools.http_request(
                method="POST",
                url=target,
                headers={"Content-Type": "application/json"},
                body='{"email":"scanlead-rate-check@invalid","password":"x"}',
                max_body_bytes=2000,
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"), n=i)
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            statuses.append(code)
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            if code == 429 or "retry-after" in headers or "rate" in (headers.get("x-ratelimit-remaining") or ""):
                throttled = True
            if headers.get("x-ratelimit-remaining") == "0":
                throttled = True
        elapsed = time.monotonic() - t0

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["rate_limit_probe"] = {
            "target": target,
            "statuses": statuses,
            "throttled": throttled,
            "elapsed_sec": round(elapsed, 2),
        }

        if statuses and not throttled and all(s < 500 for s in statuses):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="No rate limiting observed on auth-like endpoint (5-request burst)",
                    evidence_url=target,
                    evidence_snippet=f"statuses={statuses}",
                    fix="Add IP/account rate limits and lockouts on authentication endpoints.",
                    tags=["rate-limit", "auth"],
                )
            )
