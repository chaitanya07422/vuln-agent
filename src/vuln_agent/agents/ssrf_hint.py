from __future__ import annotations

import re
from typing import List
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qsl

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only SSRF hints: URL-taking params + acceptance signals for private/metadata URLs.
# Does NOT fetch cloud metadata or scan internal networks.

URL_PARAMS = (
    "url",
    "uri",
    "path",
    "dest",
    "destination",
    "redirect",
    "next",
    "image",
    "img",
    "src",
    "source",
    "webhook",
    "callback",
    "feed",
    "link",
    "target",
    "fetch",
    "proxy",
    "file",
)

# Markers that suggest the server attempted to process the URL (not a confirmed SSRF)
ACCEPT_HINTS = (
    "connection refused",
    "connection timed out",
    "name or service not known",
    "nodename nor servname",
    "getaddrinfo",
    "failed to connect",
    "could not resolve",
    "econnrefused",
    "etimedout",
    "169.254.169.254",
    "metadata",
)

PRIVATE_PROBES = (
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
)

PATHS = (
    "/api/fetch",
    "/api/proxy",
    "/api/webhook",
    "/api/hooks",
    "/api/preview",
    "/api/image",
    "/api/og",
    "/api/link-preview",
    "/webhook",
    "/proxy",
)

PARAM_IN_HTML = re.compile(
    r"""(?:name|id)=["'](%s)["']""" % "|".join(URL_PARAMS),
    re.I,
)


class SsrfHintAgent(BaseAgent):
    name = "ssrf_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=150_000)
        html = (home.get("body") or "") if home.get("ok") else ""
        params_found: List[str] = sorted({m.group(1).lower() for m in PARAM_IN_HTML.finditer(html)})

        targets = []
        for path in PATHS:
            targets.append(urljoin(base, path.lstrip("/")))
        # homepage with query params
        for p in (params_found or list(URL_PARAMS[:6]))[:4]:
            targets.append(ctx.url)

        hits = []
        seen = set()
        for target in targets[:12]:
            if not in_scope(target, ctx.scope.allow_hosts):
                continue
            for param in (params_found or ["url", "webhook", "image"])[:3]:
                for probe in PRIVATE_PROBES[:2]:
                    key = (target, param, probe)
                    if key in seen:
                        continue
                    seen.add(key)
                    if len(seen) > 18:
                        break
                    parsed = urlparse(target)
                    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                    q[param] = probe
                    probe_url = urlunparse(parsed._replace(query=urlencode(q)))
                    # GET
                    resp = await ctx.tools.http_request(method="GET", url=probe_url, max_body_bytes=8000)
                    await ctx.audit_event(agent=self.name, tool="http_request", url=probe_url, ok=resp.get("ok"))
                    body = ((resp.get("body") or "") if resp.get("ok") else "").lower()
                    code = resp.get("status_code") or 0 if resp.get("ok") else 0
                    if any(h in body for h in ACCEPT_HINTS) or (
                        code in (200, 500, 502, 504) and "169.254" in probe and ("meta" in body or "timeout" in body or "refused" in body)
                    ):
                        hits.append({"url": target, "param": param, "probe": probe, "status": code})
                        await ctx.emit_finding(
                            Finding(
                                agent=self.name,
                                severity="medium",
                                title=f"Possible SSRF-prone URL parameter '{param}'",
                                evidence_url=probe_url,
                                evidence_snippet=f"HTTP {code}; response hints server-side fetch of private URL",
                                fix="Allowlist outbound destinations; block link-local/metadata/loopback; never fetch user URLs server-side without SSRF controls.",
                                tags=["ssrf", "access"],
                            )
                        )
                        break
                # POST JSON once per path
                post = await ctx.tools.http_request(
                    method="POST",
                    url=target if "?" not in target else target.split("?")[0],
                    headers={"Content-Type": "application/json"},
                    body=f'{{"{param}":"{PRIVATE_PROBES[0]}"}}',
                    max_body_bytes=8000,
                )
                if post.get("ok"):
                    body = (post.get("body") or "").lower()
                    code = post.get("status_code") or 0
                    if any(h in body for h in ACCEPT_HINTS):
                        hits.append({"url": target, "param": param, "via": "POST", "status": code})
                        await ctx.emit_finding(
                            Finding(
                                agent=self.name,
                                severity="medium",
                                title=f"Possible SSRF-prone JSON field '{param}'",
                                evidence_url=target,
                                evidence_snippet=f"HTTP {code}; server-side fetch error for loopback/metadata URL",
                                fix="Validate and allowlist URLs; disable access to link-local and cloud metadata ranges.",
                                tags=["ssrf", "api"],
                            )
                        )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["ssrf_hint"] = {"params": params_found[:10], "hits": hits[:10]}
