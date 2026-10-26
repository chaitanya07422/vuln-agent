from __future__ import annotations

import re
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: CSRF token / SameSite gaps on state-changing forms. No forged cross-site posts.

FORM_RE = re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.I | re.S)
ACTION_RE = re.compile(r"""\baction=["']([^"']*)["']""", re.I)
METHOD_RE = re.compile(r"""\bmethod=["']([^"']*)["']""", re.I)
TOKEN_NAME = re.compile(
    r"""\bname=["']([^"']*(?:csrf|xsrf|_token|authenticity_token|__requestverificationtoken)[^"']*)["']""",
    re.I,
)
META_CSRF = re.compile(
    r"""<meta[^>]+name=["'](?:csrf-token|csrf|_csrf|xsrf-token)["'][^>]*>""",
    re.I,
)


class CsrfFormsAgent(BaseAgent):
    name = "csrf_forms"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=200_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        html = resp.get("body") or ""
        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        cookie_blob = " ".join(resp.get("set_cookie") or []) or (headers.get("set-cookie") or "")
        has_meta = bool(META_CSRF.search(html))
        samesite = "samesite" in cookie_blob.lower()
        samesite_none = "samesite=none" in cookie_blob.lower()

        risky = []
        for fm in FORM_RE.finditer(html):
            attrs, inner = fm.group(1), fm.group(2)
            method = (METHOD_RE.search(attrs).group(1) if METHOD_RE.search(attrs) else "GET").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            action = ACTION_RE.search(attrs).group(1) if ACTION_RE.search(attrs) else ctx.url
            has_token = bool(TOKEN_NAME.search(inner)) or has_meta
            if not has_token:
                risky.append(action or "/")

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["csrf_forms"] = {
            "post_forms_missing_token": risky[:10],
            "meta_csrf": has_meta,
            "samesite": samesite,
            "samesite_none": samesite_none,
        }

        for action in risky[:5]:
            target = urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", action.lstrip("/") if action.startswith("/") else action)
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="State-changing form may lack CSRF token",
                    evidence_url=target,
                    evidence_snippet=f"POST-like form action={action!r} without csrf/_token field or meta csrf-token",
                    fix="Add anti-CSRF tokens (and Prefer SameSite=Lax/Strict on session cookies).",
                    tags=["csrf", "auth"],
                )
            )

        if cookie_blob and not samesite:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="Session cookie missing SameSite attribute",
                    evidence_url=ctx.url,
                    evidence_snippet="Set-Cookie without SameSite",
                    fix="Set SameSite=Lax (or Strict) on session cookies to reduce CSRF risk.",
                    tags=["csrf", "cookies"],
                )
            )
        elif samesite_none and risky:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="SameSite=None cookie with token-less POST forms",
                    evidence_url=ctx.url,
                    evidence_snippet="SameSite=None plus POST forms without CSRF tokens",
                    fix="Require CSRF tokens when using SameSite=None; prefer Lax for session cookies.",
                    tags=["csrf", "cookies"],
                )
            )
