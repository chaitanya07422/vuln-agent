from __future__ import annotations

from urllib.parse import urljoin, urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: open-redirect param checks on login/OAuth-style URLs. No phishing.

PARAMS = ("next", "redirect", "redirect_uri", "return", "returnUrl", "return_to", "continue", "url", "dest", "destination")
PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/accounts/login",
    "/oauth/authorize",
    "/api/auth/signin",
    "/wp-login.php",
)
EVIL_HOST = "example.com.evil.invalid"
EVIL = f"https://{EVIL_HOST}/scanlead-redirect-check"


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_external_nav(location: str, origin_host: str) -> bool:
    """True if Location sends the browser to a different host (absolute URL)."""
    if not location:
        return False
    loc = location.strip()
    if loc.startswith("/") and not loc.startswith("//"):
        return False  # relative — same origin
    host = _host(loc if "://" in loc or loc.startswith("//") else f"https://{loc}")
    if loc.startswith("//"):
        host = _host("https:" + loc)
    if not host:
        return False
    return host != origin_host and EVIL_HOST in host


class RedirectOpenAgent(BaseAgent):
    name = "redirect_open"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        origin_host = _host(ctx.url)
        hits = []
        for path in PATHS:
            for param in PARAMS[:6]:
                target = urljoin(base, path.lstrip("/"))
                sep = "&" if "?" in target else "?"
                probe = f"{target}{sep}{param}={EVIL}"
                # Do not follow redirects — need the first Location hop
                resp = await ctx.tools.http_request(
                    method="GET",
                    url=probe,
                    max_body_bytes=4000,
                    follow_redirects=False,
                )
                await ctx.audit_event(agent=self.name, tool="http_request", url=probe, ok=resp.get("ok"))
                if not resp.get("ok"):
                    continue
                code = resp.get("status_code") or 0
                if code in (404, 410):
                    continue

                headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
                loc = headers.get("location") or ""
                body = (resp.get("body") or "").lower()

                # HIGH only: 3xx (or equivalent) with Location to evil external host
                if 300 <= code < 400 and _is_external_nav(loc, origin_host):
                    hits.append({"path": path, "param": param, "location": loc})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title=f"Open redirect via '{param}' on {path}",
                            evidence_url=probe,
                            evidence_snippet=f"HTTP {code} Location={loc}",
                            fix="Allowlist relative paths only; never redirect to arbitrary absolute URLs.",
                            tags=["redirect", "oauth"],
                        )
                    )
                    break

                # Meta refresh / JS — reflection only, not confirmed navigation
                if EVIL_HOST in body and ("location" in body or "redirect" in body or "meta" in body):
                    hits.append({"path": path, "param": param, "via": "body"})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="low",
                            title=f"Redirect parameter reflected in response on {path}",
                            evidence_url=probe,
                            evidence_snippet="evil host reflected in body (not a confirmed Location hop)",
                            fix="Validate redirect targets server-side before emitting links or meta refresh.",
                            tags=["redirect"],
                        )
                    )
                    break
            if len(hits) >= 3:
                break

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["redirect_open"] = {"hits": hits}
