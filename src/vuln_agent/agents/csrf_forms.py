from __future__ import annotations

import re
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.cookie_flags import is_bot_or_analytics_cookie, parse_cookie, split_set_cookie_header
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: CSRF token / SameSite gaps on state-changing forms. No forged cross-site posts.


def _session_like_cookies(cookie_headers: list[str]) -> list[str]:
    """Cookie names that look like app sessions (exclude bot/CDN/analytics)."""
    names: list[str] = []
    for raw in cookie_headers:
        for part in split_set_cookie_header(raw) if "," in raw and "expires=" in raw.lower() else [raw]:
            parsed = parse_cookie(part)
            if not parsed:
                continue
            name, _value, _attrs, is_delete = parsed
            if is_delete or is_bot_or_analytics_cookie(name):
                continue
            names.append(name)
    return names


def _cookie_missing_samesite(cookie_headers: list[str], name: str) -> bool:
    lname = name.lower()
    for raw in cookie_headers:
        parts = split_set_cookie_header(raw) if "," in raw else [raw]
        for part in parts:
            parsed = parse_cookie(part)
            if not parsed:
                continue
            n, _v, attrs, _d = parsed
            if n.lower() != lname:
                continue
            return "samesite" not in f"{n};{attrs}".lower()
    return False

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
        cookie_headers: list[str] = list(resp.get("set_cookie") or [])
        if not cookie_headers and headers.get("set-cookie"):
            cookie_headers = split_set_cookie_header(headers["set-cookie"])
        cookie_blob = " ".join(cookie_headers)
        has_meta = bool(META_CSRF.search(html))
        session_cookies = _session_like_cookies(cookie_headers)
        session_missing_samesite = [
            n for n in session_cookies if _cookie_missing_samesite(cookie_headers, n)
        ]
        samesite_none = False
        for raw in cookie_headers:
            parts = split_set_cookie_header(raw) if "," in raw else [raw]
            for part in parts:
                parsed = parse_cookie(part)
                if not parsed:
                    continue
                name, _value, attrs, is_delete = parsed
                if is_delete or is_bot_or_analytics_cookie(name):
                    continue
                if "samesite=none" in f"{name};{attrs}".lower():
                    samesite_none = True
                    break
            if samesite_none:
                break

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
            "session_cookies": session_cookies[:10],
            "session_missing_samesite": session_missing_samesite[:10],
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

        # Only flag SameSite gaps on app session-like cookies — never Akamai/bot cookies alone
        if session_missing_samesite:
            shown = ", ".join(session_missing_samesite[:3])
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="Session cookie missing SameSite attribute",
                    evidence_url=ctx.url,
                    evidence_snippet=f"Set-Cookie without SameSite for: {shown}",
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
