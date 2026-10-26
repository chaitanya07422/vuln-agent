from __future__ import annotations

import re
from typing import Set
from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.safety import is_blocked_hostname, resolve_public_ips

# Detect-only: cert SAN / DNS / HTML link hints. No mass subdomain brute.

HREF_HOST = re.compile(r"""https?://([a-z0-9._-]+\.[a-z]{2,})""", re.I)


class SubdomainHintAgent(BaseAgent):
    name = "subdomain_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host.lower()
        apex = host[4:] if host.startswith("www.") else host
        found: Set[str] = set()

        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=200_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if home.get("ok"):
            body = home.get("body") or ""
            for m in HREF_HOST.finditer(body):
                h = m.group(1).lower().rstrip(".")
                if h.endswith("." + apex) or h == apex:
                    found.add(h)

        # Light DNS candidates (no brute dictionary)
        for prefix in ("www", "mail", "api", "app", "staging", "dev", "uat", "cdn", "static", "admin"):
            cand = f"{prefix}.{apex}"
            if is_blocked_hostname(cand):
                continue
            dns = await ctx.tools.dns_lookup(host=cand)
            if dns.get("ok") and dns.get("addresses") and resolve_public_ips(cand):
                found.add(cand)

        # Certificate transparency-ish: try openssl s_client SAN if available — skip heavy; use HTTPS peer cert via headers only
        # Many CDNs expose via link headers
        if home.get("ok"):
            headers = {k.lower(): v for k, v in (home.get("headers") or {}).items()}
            for key in ("link", "content-security-policy", "report-to"):
                val = headers.get(key) or ""
                for m in HREF_HOST.finditer(val):
                    h = m.group(1).lower()
                    if h.endswith("." + apex):
                        found.add(h)

        # Drop apex/www noise for findings; keep in fingerprint
        extras = sorted(h for h in found if h not in {apex, f"www.{apex}", host})
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["subdomain_hint"] = {"hosts": sorted(found)[:30]}

        # Interesting prefixes only as low findings
        interesting = [
            h
            for h in extras
            if any(h.startswith(p + ".") for p in ("staging", "dev", "uat", "admin", "test", "internal"))
        ]
        for h in interesting[:5]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title=f"Non-prod-looking host resolves: {h}",
                    evidence_url=ctx.url,
                    evidence_snippet=h,
                    fix="Keep staging off the public internet or lock behind VPN/SSO.",
                    tags=["subdomain", "staging"],
                )
            )
