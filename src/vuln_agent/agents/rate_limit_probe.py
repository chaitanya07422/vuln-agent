from __future__ import annotations

import time
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import looks_like_html_document
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: soft burst (hard cap 5) on login/API; "no throttle" note. No sprays.

AUTH_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/api/login",
    "/api/auth/login",
    "/api/auth/signin",
    "/api/auth/callback",
    "/wp-login.php",
    "/accounts/login",
)


class RateLimitProbeAgent(BaseAgent):
    name = "rate_limit_probe"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        target = None
        for path in AUTH_PATHS:
            url = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=url, max_body_bytes=4000)
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            if code in (404, 410):
                continue
            body = resp.get("body") or ""
            headers = resp.get("headers") or {}
            # Soft-404 SPA shells that aren't login-like — skip
            if code == 200 and looks_like_html_document(body, headers):
                lower = body.lower()
                if not any(x in lower for x in ("password", "sign in", "log in", "username", "email")):
                    continue
            if code in (200, 401, 403, 405):
                target = url
                break

        ctx.fingerprint = dict(ctx.fingerprint or {})
        if not target:
            # Do NOT fall back to homepage — that produces misleading findings
            ctx.fingerprint["rate_limit_probe"] = {"skipped": True, "reason": "no_auth_endpoint"}
            return

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
            if code == 429 or "retry-after" in headers:
                throttled = True
            rem = headers.get("x-ratelimit-remaining")
            if rem == "0" or (rem is not None and "rate" in (headers.get("x-ratelimit-remaining") or "")):
                throttled = True
        elapsed = time.monotonic() - t0

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
                    title=f"No rate limiting observed on {target} (5-request burst)",
                    evidence_url=target,
                    evidence_snippet=f"statuses={statuses}",
                    fix="Add IP/account rate limits and lockouts on authentication endpoints.",
                    tags=["rate-limit", "auth"],
                )
            )
