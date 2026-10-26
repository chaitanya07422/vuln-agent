from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: response header presence; no TLS downgrade or cipher brute.

IMPORTANT = {
    "strict-transport-security": ("medium", "Missing Strict-Transport-Security", "Add HSTS with a sensible max-age on HTTPS responses."),
    "content-security-policy": ("low", "Missing Content-Security-Policy", "Add a CSP appropriate for the app; start report-only if needed."),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("low", "Missing X-Frame-Options / frame-ancestors", "Set X-Frame-Options: DENY (or CSP frame-ancestors)."),
    "referrer-policy": ("info", "Missing Referrer-Policy", "Set Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
    "permissions-policy": ("info", "Missing Permissions-Policy", "Restrict powerful browser features via Permissions-Policy."),
}


class TlsHeadersAgent(BaseAgent):
    name = "tls_headers"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["security_headers"] = {
            k: (k in headers) for k in IMPORTANT
        }

        # Prefer CSP frame-ancestors over XFO when CSP present
        has_csp = "content-security-policy" in headers
        csp_val = headers.get("content-security-policy") or ""
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()

        missing = []
        for name, (sev, title, fix) in IMPORTANT.items():
            if name in headers:
                continue
            if name == "x-frame-options" and has_frame_ancestors:
                continue
            if name == "content-security-policy" and has_csp:
                continue
            missing.append(name)
            if sev == "info":
                continue
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    evidence_url=ctx.url,
                    evidence_snippet=f"Response lacked {name}",
                    fix=fix,
                    tags=["headers", "tls", name],
                )
            )

        # Light TLS note: HTTPS URL served without HSTS
        if ctx.url.lower().startswith("https://") and "strict-transport-security" not in headers:
            # already emitted medium above
            pass

        ctx.fingerprint["security_headers_missing"] = missing
