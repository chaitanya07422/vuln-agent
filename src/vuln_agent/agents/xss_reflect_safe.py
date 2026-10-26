from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: unique safe marker reflection + CSP gaps. No <script> or event-handler payloads.

MARKER = "scanleadXssMarker7f3a"
PARAMS = ("q", "query", "search", "s", "name", "msg", "message", "error", "text", "keyword", "term")
PATHS = ("/", "/search", "/api/search", "/login", "/contact", "/?")


class XssReflectSafeAgent(BaseAgent):
    name = "xss_reflect_safe"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=100_000)
        headers = {k.lower(): v for k, v in ((home.get("headers") or {}) if home.get("ok") else {}).items()}
        csp = headers.get("content-security-policy") or ""
        weak_csp = (not csp) or ("unsafe-inline" in csp.lower() and "script-src" in csp.lower())

        if not csp:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="No Content-Security-Policy (XSS mitigation gap)",
                    evidence_url=ctx.url,
                    evidence_snippet="CSP header absent",
                    fix="Deploy a CSP that avoids unsafe-inline for scripts where possible.",
                    tags=["xss", "csp", "headers"],
                )
            )
        elif "unsafe-inline" in csp.lower():
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="CSP allows unsafe-inline",
                    evidence_url=ctx.url,
                    evidence_snippet=csp[:200],
                    tags=["xss", "csp"],
                )
            )

        reflections = []
        for path in PATHS:
            for param in PARAMS[:5]:
                target = urljoin(base, path.lstrip("/")) if path != "/?" else ctx.url
                parsed = urlparse(target)
                q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                q[param] = MARKER
                probe = urlunparse(parsed._replace(query=urlencode(q)))
                if not in_scope(probe, ctx.scope.allow_hosts):
                    continue
                resp = await ctx.tools.http_request(method="GET", url=probe, max_body_bytes=80_000)
                await ctx.audit_event(agent=self.name, tool="http_request", url=probe, ok=resp.get("ok"))
                if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
                    continue
                body = resp.get("body") or ""
                if MARKER not in body:
                    continue
                # Context: raw in HTML vs inside attribute/script-ish
                idx = body.find(MARKER)
                window = body[max(0, idx - 40) : idx + len(MARKER) + 40]
                in_tag = bool(re.search(r"<[^>]*%s" % re.escape(MARKER), window))
                unescaped = MARKER in body and f"&lt;" not in body[idx : idx + 20]
                reflections.append({"param": param, "path": path, "window": window[:120]})
                sev = "medium" if unescaped or in_tag or weak_csp else "low"
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        title=f"Reflected input in response via '{param}'",
                        evidence_url=probe,
                        evidence_snippet=window[:160],
                        fix="Context-encode output (HTML/attr/JS); prefer CSP without unsafe-inline; never reflect raw user input.",
                        tags=["xss", "reflection"],
                    )
                )
                break
            if len(reflections) >= 4:
                break

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["xss_reflect_safe"] = {
            "csp": bool(csp),
            "reflections": reflections[:8],
        }
