from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.dns_txt import dig_records, txt_has_dmarc, txt_has_spf

# Detect-only: SPF/DMARC/DKIM selector presence via DNS. No spoof send tests.


class EmailSpoofAgent(BaseAgent):
    name = "email_spoof"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host
        apex = host[4:] if host.lower().startswith("www.") else host

        spf = await dig_records(apex, "TXT")
        dmarc = await dig_records(f"_dmarc.{apex}", "TXT")
        # Common DKIM selectors — presence only
        dkim_hits = []
        for sel in ("default", "google", "selector1", "selector2", "k1", "s1"):
            r = await dig_records(f"{sel}._domainkey.{apex}", "TXT")
            if r.get("ok") and r.get("records"):
                dkim_hits.append(sel)

        spf_ok = txt_has_spf(spf.get("records") or [])
        dmarc_ok = txt_has_dmarc(dmarc.get("records") or [])
        dmarc_records = dmarc.get("records") or []
        policy_none = any("p=none" in r.lower() for r in dmarc_records)

        await ctx.audit_event(
            agent=self.name,
            tool="dns_txt",
            result={"spf": spf_ok, "dmarc": dmarc_ok, "dkim": dkim_hits},
        )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["email_spoof"] = {
            "spf": spf_ok,
            "dmarc": dmarc_ok,
            "dkim_selectors": dkim_hits,
            "dmarc_policy_none": policy_none,
        }

        if spf.get("error") == "dig_unavailable":
            return

        if not spf_ok:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="No SPF record on apex",
                    evidence_url=ctx.url,
                    evidence_snippet=f"TXT lookup for {apex} had no v=spf1",
                    fix="Publish an SPF TXT record listing authorized senders.",
                    tags=["email", "spf"],
                )
            )
        if not dmarc_ok:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="No DMARC record",
                    evidence_url=ctx.url,
                    evidence_snippet=f"No v=DMARC1 at _dmarc.{apex}",
                    fix="Publish a DMARC policy (start with p=none + rua, then quarantine/reject).",
                    tags=["email", "dmarc"],
                )
            )
        elif policy_none:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="DMARC policy is p=none",
                    evidence_url=ctx.url,
                    evidence_snippet="; ".join(dmarc_records)[:200],
                    fix="Monitor rua reports, then move to p=quarantine or p=reject.",
                    tags=["email", "dmarc"],
                )
            )
        if not dkim_hits and (spf_ok or dmarc_ok):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="No common DKIM selectors found",
                    evidence_url=ctx.url,
                    evidence_snippet="Tried default/google/selector1/selector2/k1/s1",
                    fix="Enable DKIM at your ESP and publish the selector TXT record.",
                    tags=["email", "dkim"],
                )
            )
