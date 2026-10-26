from __future__ import annotations

from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import looks_like_html_document
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: one-shot HEAD/GET of stack-keyed admin paths. No login attempts.

STACK_PATHS = {
    "wordpress": ["/wp-admin/", "/wp-login.php"],
    "nextjs": ["/admin", "/dashboard", "/api/auth/signin"],
    "express": ["/admin", "/admin/login", "/dashboard"],
    "nestjs": ["/admin", "/api/admin"],
    "shopify": ["/admin"],
    "unknown": ["/admin", "/administrator", "/manager", "/console", "/login"],
}

GENERIC = ["/admin", "/administrator", "/phpmyadmin/", "/adminer.php", "/server-status"]


class AdminPanelsAgent(BaseAgent):
    name = "admin_panels"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        paths = list(GENERIC)
        for t in tags:
            paths.extend(STACK_PATHS.get(t, []))
        # de-dupe preserve order
        seen = set()
        ordered = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                ordered.append(p)

        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        found = []
        for path in ordered[:12]:
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=12000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            body = resp.get("body") or ""
            headers = resp.get("headers") or {}
            if code in (401, 403):
                found.append({"path": path, "status": code})
                continue
            if code != 200:
                continue
            lower = body.lower()
            looks_login = any(
                x in lower
                for x in (
                    "password",
                    "wp-login",
                    "sign in",
                    "log in",
                    "username",
                    "admin panel",
                    "dashboard",
                )
            )
            if looks_like_html_document(body, headers) and looks_login:
                found.append({"path": path, "status": code})
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title=f"Admin/login surface reachable: {path}",
                        evidence_url=target,
                        evidence_snippet=f"HTTP {code}; login-like page content",
                        fix="Restrict admin paths by IP/VPN; enforce MFA; avoid public discovery where possible.",
                        tags=["admin", "exposure"],
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["admin_panels"] = found[:10]
