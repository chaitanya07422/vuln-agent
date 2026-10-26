from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: origin/panel leakage via headers or verbose errors.

ORIGIN_HINT_HEADERS = (
    "x-origin",
    "x-backend",
    "x-real-ip",
    "x-served-by",
    "x-cache-hits",
    "x-powered-by",
    "via",
    "x-amz-cf-id",
    "cf-ray",
    "x-azure-ref",
    "x-vercel-id",
    "x-debug",
    "x-generation",
)


class CdnOriginAgent(BaseAgent):
    name = "cdn_origin"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=20_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        body = (resp.get("body") or "").lower()
        interesting = {k: headers[k] for k in ORIGIN_HINT_HEADERS if k in headers}

        # Probe a nonsense path for verbose origin errors
        from urllib.parse import urljoin

        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        boom = urljoin(base, f"scanlead-cdn-probe-{ctx.scan_id[:8] if ctx.scan_id else 'x'}")
        err = await ctx.tools.http_request(method="GET", url=boom, max_body_bytes=12_000)
        err_body = (err.get("body") or "") if err.get("ok") else ""
        err_l = err_body.lower()

        leaks = []
        for needle in (
            "traceback",
            "at com.",
            "at org.",
            "nginx/",
            "apache/",
            "gunicorn",
            "werkzeug",
            "x-amzn-",
            "elb.amazonaws",
            "internal-",
            "10.",
            "172.16.",
            "192.168.",
        ):
            if needle in err_l or needle in body:
                # Avoid flagging private IP in normal marketing pages lightly
                if needle.startswith(("10.", "172.", "192.")) and needle not in err_l:
                    continue
                leaks.append(needle)

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cdn_origin"] = {"headers": interesting, "error_hints": leaks[:10]}

        # Private IP / internal hostname in error page
        if any(x in err_l for x in ("traceback", "at com.", "at org.springframework", "werkzeug.debug")):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="Verbose application error / stack trace exposed",
                    evidence_url=boom,
                    evidence_snippet=err_body[:200],
                    fix="Return generic error pages publicly; keep stack traces in private logs.",
                    tags=["cdn", "errors"],
                )
            )

        for k, v in interesting.items():
            vl = v.lower()
            if any(x in vl for x in ("10.", "172.16.", "192.168.", "internal", "localhost", "127.0.0.1")):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"Header '{k}' may leak origin/network detail",
                        evidence_url=ctx.url,
                        evidence_snippet=f"{k}: {v[:160]}",
                        fix="Strip internal headers at the CDN/edge before responses leave the perimeter.",
                        tags=["cdn", "headers"],
                    )
                )
