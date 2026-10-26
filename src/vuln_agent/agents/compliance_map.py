from __future__ import annotations

from collections import defaultdict

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext

# Report-layer: map findings → OWASP-style tags in fingerprint/summary. No new probes.

OWASP_MAP = {
    "A01: Broken Access Control": {"admin", "users", "auth", "oauth", "redirect", "actuator", "access", "idor", "ssrf", "csrf"},
    "A02: Cryptographic Failures": {"tls", "secrets", "jwt", "dkim", "spf", "dmarc", "cookies", "cert"},
    "A03: Injection": {"graphql", "xmlrpc", "input", "validation", "xss", "reflection"},
    "A04: Insecure Design": {"rate-limit", "cors", "client-validation"},
    "A05: Security Misconfiguration": {
        "headers",
        "cors",
        "methods",
        "cloud",
        "listing",
        "spring",
        "wordpress",
        "firebase",
        "sourcemap",
        "cdn",
        "cache",
        "csp",
        "cve",
    },
    "A07: Identification & Auth Failures": {"auth", "oauth", "session", "jwt", "cookies", "enum", "mfa", "reset"},
    "A09: Security Logging & Monitoring": {"rate-limit"},
    "A10: SSRF": {"redirect", "oauth", "ssrf"},
}


class ComplianceMapAgent(BaseAgent):
    name = "compliance_map"
    requires_tags: list = []
    skip_if_tags: list = []

    async def run(self, ctx: ScanContext) -> None:
        buckets = defaultdict(list)
        for f in list(ctx.findings):
            if f.severity == "info":
                continue
            tags = {t.lower() for t in (f.tags or [])}
            title_l = (f.title or "").lower()
            matched = []
            for owasp, keys in OWASP_MAP.items():
                if tags & keys or any(k in title_l for k in keys):
                    matched.append(owasp)
                    buckets[owasp].append(f.title)
            if matched:
                # annotate finding tags (non-destructive)
                for m in matched:
                    short = m.split(":")[0].strip()
                    if short not in f.tags:
                        f.tags = list(f.tags or []) + [short]

        summary = {
            k: v[:8]
            for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        }
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["compliance_map"] = summary
        if ctx.summary is None:
            ctx.summary = {}
        # stash for UI if summary already built later — reporter will rebuild
        ctx.fingerprint["owasp_attention"] = list(summary.keys())[:8]
