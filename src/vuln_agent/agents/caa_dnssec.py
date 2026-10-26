from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.dns_txt import dig_records

# Detect-only: CAA + DNSSEC presence for apex.


class CaaDnssecAgent(BaseAgent):
    name = "caa_dnssec"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host
        apex = host[4:] if host.lower().startswith("www.") else host

        caa = await dig_records(apex, "CAA")
        dnskey = await dig_records(apex, "DNSKEY")
        ds = await dig_records(apex, "DS")

        await ctx.audit_event(
            agent=self.name,
            tool="dns",
            result={
                "caa": caa.get("records"),
                "dnskey": bool(dnskey.get("records")),
                "ds": bool(ds.get("records")),
            },
        )

        has_caa = bool(caa.get("records"))
        has_dnssec = bool(dnskey.get("records") or ds.get("records"))

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["caa_dnssec"] = {
            "caa": caa.get("records") or [],
            "dnssec": has_dnssec,
        }

        if caa.get("error") == "dig_unavailable":
            return

        if not has_caa:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="No CAA DNS records on apex",
                    evidence_url=ctx.url,
                    evidence_snippet=f"CAA lookup empty for {apex}",
                    fix="Publish CAA records limiting which CAs may issue certificates for your domain.",
                    tags=["dns", "caa"],
                )
            )
        if not has_dnssec:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="DNSSEC not detected on apex",
                    evidence_url=ctx.url,
                    evidence_snippet="No DNSKEY/DS in dig +short",
                    tags=["dns", "dnssec"],
                )
            )
