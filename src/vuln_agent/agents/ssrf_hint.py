from __future__ import annotations

import re
from typing import List, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

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

# Strong signals that the server attempted an outbound fetch of the probe URL.
# Avoid bare tokens like "metadata" — Next.js/React HTML often contains that word.
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
    "enotfound",
    "errno -111",
    "errno 111",
    "connect econnrefused",
    "socket hang up",
    "169.254.169.254",
    "meta-data/",
    "latest/meta-data",
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

# Generic SPA/framework 404 shells — not evidence of URL fetching.
NOISE_BODY_MARKERS = (
    "this page could not be found",
    "404: this page could not be found",
    "__next_f",
    "next-error-h1",
)


def _norm_body(body: str) -> str:
    return re.sub(r"\s+", " ", (body or "").lower())[:4000]


def _looks_like_generic_shell(body: str) -> bool:
    b = _norm_body(body)
    if not b:
        return True
    return any(m in b for m in NOISE_BODY_MARKERS)


def _strong_accept(body: str, *, probe: str, code: int) -> bool:
    """True only when body/status suggest the server tried the probe URL."""
    b = (body or "").lower()
    if not b:
        return False
    if _looks_like_generic_shell(b):
        return False
    if any(h in b for h in ACCEPT_HINTS):
        return True
    # Cloud metadata probe: only when status is error-like AND body has
    # metadata-path tokens (not the bare word "metadata").
    if code in (200, 500, 502, 504) and "169.254" in probe:
        if "meta-data" in b or "ami-id" in b or "instance-id" in b:
            return True
        if ("timeout" in b or "refused" in b) and ("connect" in b or "network" in b):
            return True
    return False


def _same_response(a_code: int, a_body: str, b_code: int, b_body: str) -> bool:
    """Baseline vs probe: same status + near-identical body ⇒ param ignored."""
    if a_code != b_code:
        return False
    na, nb = _norm_body(a_body), _norm_body(b_body)
    if not na and not nb:
        return True
    if na == nb:
        return True
    # Tolerate tiny diffs (timestamps, request ids)
    if abs(len(na) - len(nb)) <= 32 and na[:200] == nb[:200]:
        return True
    return False


class SsrfHintAgent(BaseAgent):
    name = "ssrf_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=150_000)
        html = (home.get("body") or "") if home.get("ok") else ""
        params_found: List[str] = sorted({m.group(1).lower() for m in PARAM_IN_HTML.finditer(html)})

        targets: List[str] = []
        for path in PATHS:
            targets.append(urljoin(base, path.lstrip("/")))
        # Homepage only when HTML actually exposes URL-like form fields
        if params_found:
            targets.append(ctx.url)

        hits = []
        seen: Set[Tuple[str, str, str]] = set()
        baseline_cache: dict[str, Tuple[int, str]] = {}
        emitted_params: Set[Tuple[str, str, str]] = set()  # path, param, method

        for target in targets[:12]:
            if not in_scope(target, ctx.scope.allow_hosts):
                continue
            path_key = urlparse(target)._replace(query="", fragment="").geturl()
            params = (params_found or ["url", "webhook", "image"])[:3]

            # Baseline GET without SSRF probe params
            if path_key not in baseline_cache:
                base_resp = await ctx.tools.http_request(method="GET", url=path_key, max_body_bytes=8000)
                if base_resp.get("ok"):
                    baseline_cache[path_key] = (
                        int(base_resp.get("status_code") or 0),
                        base_resp.get("body") or "",
                    )
                else:
                    baseline_cache[path_key] = (0, "")

            base_code, base_body = baseline_cache[path_key]

            # POST baseline once per path
            post_base_key = f"POST:{path_key}"
            if post_base_key not in baseline_cache:
                post_base = await ctx.tools.http_request(
                    method="POST",
                    url=path_key,
                    headers={"Content-Type": "application/json"},
                    body="{}",
                    max_body_bytes=8000,
                )
                if post_base.get("ok"):
                    baseline_cache[post_base_key] = (
                        int(post_base.get("status_code") or 0),
                        post_base.get("body") or "",
                    )
                else:
                    baseline_cache[post_base_key] = (0, "")
            pb_code, pb_body = baseline_cache[post_base_key]

            for param in params:
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
                    resp = await ctx.tools.http_request(method="GET", url=probe_url, max_body_bytes=8000)
                    await ctx.audit_event(agent=self.name, tool="http_request", url=probe_url, ok=resp.get("ok"))
                    if not resp.get("ok"):
                        continue
                    body = resp.get("body") or ""
                    code = int(resp.get("status_code") or 0)
                    # Param ignored / generic 404 shell → not SSRF
                    if _same_response(base_code, base_body, code, body):
                        continue
                    if not _strong_accept(body, probe=probe, code=code):
                        continue
                    emit_key = (path_key, param, "GET")
                    if emit_key in emitted_params:
                        break
                    emitted_params.add(emit_key)
                    hits.append({"url": target, "param": param, "probe": probe, "status": code})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"Possible SSRF-prone URL parameter '{param}'",
                            evidence_url=probe_url,
                            evidence_snippet=f"HTTP {code}; body differs from baseline and shows fetch/connect error for private URL",
                            fix="Allowlist outbound destinations; block link-local/metadata/loopback; never fetch user URLs server-side without SSRF controls.",
                            tags=["ssrf", "access"],
                        )
                    )
                    break

                # POST JSON once per path+param
                post = await ctx.tools.http_request(
                    method="POST",
                    url=path_key,
                    headers={"Content-Type": "application/json"},
                    body=f'{{"{param}":"{PRIVATE_PROBES[0]}"}}',
                    max_body_bytes=8000,
                )
                if not post.get("ok"):
                    continue
                body = post.get("body") or ""
                code = int(post.get("status_code") or 0)
                if _same_response(pb_code, pb_body, code, body):
                    continue
                if not _strong_accept(body, probe=PRIVATE_PROBES[0], code=code):
                    continue
                emit_key = (path_key, param, "POST")
                if emit_key in emitted_params:
                    continue
                emitted_params.add(emit_key)
                hits.append({"url": target, "param": param, "via": "POST", "status": code})
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"Possible SSRF-prone JSON field '{param}'",
                        evidence_url=path_key,
                        evidence_snippet=f"HTTP {code}; body differs from baseline and shows fetch/connect error for loopback URL",
                        fix="Validate and allowlist URLs; disable access to link-local and cloud metadata ranges.",
                        tags=["ssrf", "api"],
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["ssrf_hint"] = {"params": params_found[:10], "hits": hits[:10]}
