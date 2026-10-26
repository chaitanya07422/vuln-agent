from __future__ import annotations

from urllib.parse import urljoin

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
EVIL = "https://example.com.evil.invalid/scanlead-redirect-check"


class RedirectOpenAgent(BaseAgent):
    name = "redirect_open"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        hits = []
        for path in PATHS:
            for param in PARAMS[:6]:
                target = urljoin(base, path.lstrip("/"))
                sep = "&" if "?" in target else "?"
                probe = f"{target}{sep}{param}={EVIL}"
                # Do not follow redirects for this check
                http = ctx.tools.http_request
                # Tool always follows redirects; inspect final URL + Location if present
                resp = await http(method="GET", url=probe, max_body_bytes=4000)
                await ctx.audit_event(agent=self.name, tool="http_request", url=probe, ok=resp.get("ok"))
                if not resp.get("ok"):
                    continue
                final = (resp.get("url") or "").lower()
                headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
                loc = (headers.get("location") or "").lower()
                body = (resp.get("body") or "").lower()
                if "example.com.evil.invalid" in final or "example.com.evil.invalid" in loc:
                    hits.append({"path": path, "param": param})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title=f"Open redirect via '{param}' on {path}",
                            evidence_url=probe,
                            evidence_snippet=f"final={resp.get('url')} location={headers.get('location')}",
                            fix="Allowlist relative paths only; never redirect to arbitrary absolute URLs.",
                            tags=["redirect", "oauth"],
                        )
                    )
                    break
                # Meta refresh / JS hint
                if "example.com.evil.invalid" in body and ("location" in body or "redirect" in body):
                    hits.append({"path": path, "param": param, "via": "body"})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"Redirect parameter reflected toward external URL on {path}",
                            evidence_url=probe,
                            evidence_snippet="evil host reflected in response body",
                            fix="Validate redirect targets server-side before emitting links or meta refresh.",
                            tags=["redirect"],
                        )
                    )
                    break
            if len(hits) >= 3:
                break

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["redirect_open"] = {"hits": hits}
