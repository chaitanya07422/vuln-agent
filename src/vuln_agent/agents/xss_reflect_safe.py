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

# Next.js / RSC often echo the URL into flight payloads (urlParts, initialTree). That is
# expected router state — not classic HTML XSS by itself.
RSC_ECHO_HINTS = (
    "urlparts",
    "initialtree",
    "__next_f",
    "self.__next_f",
    "rlparts",
    '"children"',
    "flight",
    "$sreact",
)


def _reflection_context(body: str, marker: str) -> dict:
    idx = body.find(marker)
    if idx < 0:
        return {"window": "", "in_tag": False, "rsc_echo": False, "html_context": False}
    window = body[max(0, idx - 80) : idx + len(marker) + 80]
    around = body[max(0, idx - 200) : idx + len(marker) + 200].lower()
    in_tag = bool(re.search(r"<[^>]*%s" % re.escape(marker), window))
    rsc_echo = any(h in around for h in RSC_ECHO_HINTS)
    # Classic HTML sink: marker appears in markup outside JSON/RSC blobs
    html_context = (not rsc_echo) and (
        in_tag
        or bool(re.search(r">[^<]*%s" % re.escape(marker), window))
        or '="' + marker in window
        or "='" + marker in window
    )
    return {
        "window": window[:160],
        "in_tag": in_tag,
        "rsc_echo": rsc_echo,
        "html_context": html_context,
    }


class XssReflectSafeAgent(BaseAgent):
    name = "xss_reflect_safe"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=100_000)
        headers = {k.lower(): v for k, v in ((home.get("headers") or {}) if home.get("ok") else {}).items()}
        csp = headers.get("content-security-policy") or ""

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
                ctx_info = _reflection_context(body, MARKER)
                reflections.append(
                    {
                        "param": param,
                        "path": path,
                        "window": ctx_info["window"][:120],
                        "rsc_echo": ctx_info["rsc_echo"],
                        "html_context": ctx_info["html_context"],
                    }
                )
                if ctx_info["rsc_echo"] and not ctx_info["html_context"]:
                    # Next/RSC router state echo — informational, not a medium XSS
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="info",
                            title=f"URL param '{param}' echoed in client/router state",
                            evidence_url=probe,
                            evidence_snippet=ctx_info["window"][:160],
                            fix="Expected for many SPA/RSC frameworks. Treat as XSS only if the value reaches an HTML/JS sink unencoded.",
                            tags=["xss", "reflection", "framework"],
                        )
                    )
                elif ctx_info["html_context"] or ctx_info["in_tag"]:
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"Reflected input in response via '{param}'",
                            evidence_url=probe,
                            evidence_snippet=ctx_info["window"][:160],
                            fix="Context-encode output (HTML/attr/JS); prefer CSP without unsafe-inline; never reflect raw user input.",
                            tags=["xss", "reflection"],
                        )
                    )
                else:
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="low",
                            title=f"Reflected input in response via '{param}'",
                            evidence_url=probe,
                            evidence_snippet=ctx_info["window"][:160],
                            fix="Context-encode output; confirm the sink before treating as XSS.",
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
