from __future__ import annotations

import re
import secrets
from typing import List, Optional, Set

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.safety import is_blocked_hostname, resolve_public_ips

# Detect-only: cert SAN / DNS / HTML link hints. No mass subdomain brute.

HREF_HOST = re.compile(r"""https?://([a-z0-9._-]+\.[a-z]{2,})""", re.I)

NON_PROD_PREFIXES = ("staging", "dev", "uat", "admin", "test", "internal")


def _addrs_for(host: str, dns_result: Optional[dict]) -> Set[str]:
    addrs: Set[str] = set()
    if dns_result and dns_result.get("ok"):
        for a in dns_result.get("addresses") or []:
            if a:
                addrs.add(str(a).lower())
    try:
        resolved = resolve_public_ips(host)
    except Exception:
        resolved = None
    if resolved:
        for a in resolved:
            addrs.add(str(a).lower())
    return addrs


def is_wildcard_catch_all(candidate_addrs: Set[str], wildcard_addrs: Set[str]) -> bool:
    """True when candidate resolves only to the same public IPs as a random label."""
    if not candidate_addrs or not wildcard_addrs:
        return False
    return candidate_addrs <= wildcard_addrs


class SubdomainHintAgent(BaseAgent):
    name = "subdomain_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host.lower()
        apex = host[4:] if host.startswith("www.") else host
        found: Set[str] = set()
        html_hosts: Set[str] = set()

        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=200_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if home.get("ok"):
            body = home.get("body") or ""
            for m in HREF_HOST.finditer(body):
                h = m.group(1).lower().rstrip(".")
                if h.endswith("." + apex) or h == apex:
                    found.add(h)
                    html_hosts.add(h)

        # Wildcard / catch-all DNS: random label resolving ⇒ skip DNS-only non-prod findings
        wildcard = False
        wildcard_addrs: Set[str] = set()
        rand_label = f"scanlead-nx-{secrets.token_hex(4)}"
        rand_host = f"{rand_label}.{apex}"
        if not is_blocked_hostname(rand_host):
            rand_dns = await ctx.tools.dns_lookup(host=rand_host)
            wildcard_addrs = _addrs_for(rand_host, rand_dns)
            wildcard = bool(wildcard_addrs)

        # Light DNS candidates (no brute dictionary)
        for prefix in ("www", "mail", "api", "app", "staging", "dev", "uat", "cdn", "static", "admin"):
            cand = f"{prefix}.{apex}"
            if is_blocked_hostname(cand):
                continue
            dns = await ctx.tools.dns_lookup(host=cand)
            addrs = _addrs_for(cand, dns)
            if not (dns.get("ok") and addrs):
                continue
            if wildcard and is_wildcard_catch_all(addrs, wildcard_addrs):
                # Catch-all — do not treat guessed prefixes as real hosts
                continue
            if resolve_public_ips(cand):
                found.add(cand)

        # HTTPS peer hints via headers
        if home.get("ok"):
            headers = {k.lower(): v for k, v in (home.get("headers") or {}).items()}
            for key in ("link", "content-security-policy", "report-to"):
                val = headers.get(key) or ""
                for m in HREF_HOST.finditer(val):
                    h = m.group(1).lower()
                    if h.endswith("." + apex):
                        found.add(h)
                        html_hosts.add(h)

        extras = sorted(h for h in found if h not in {apex, f"www.{apex}", host})
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["subdomain_hint"] = {
            "hosts": sorted(found)[:30],
            "wildcard_dns": wildcard,
            "wildcard_probe": rand_host if wildcard else None,
        }

        interesting: List[str] = [
            h
            for h in extras
            if any(h.startswith(p + ".") for p in NON_PROD_PREFIXES)
        ]
        # Under catch-all DNS, only keep non-prod hosts evidenced in HTML/headers
        if wildcard:
            interesting = [h for h in interesting if h in html_hosts]

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
