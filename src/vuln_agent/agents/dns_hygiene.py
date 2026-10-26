from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.dns_txt import dig_axfr_refused, dig_cname
from vuln_agent.tools.safety import resolve_public_ips

# Detect-only: dangling CNAME hints; single AXFR refuse check.


class DnsHygieneAgent(BaseAgent):
    name = "dns_hygiene"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host
        apex = host[4:] if host.lower().startswith("www.") else host

        axfr = await dig_axfr_refused(apex)
        await ctx.audit_event(agent=self.name, tool="axfr", result=axfr)
        if axfr.get("open_axfr"):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="DNS zone transfer (AXFR) appears open",
                    evidence_url=ctx.url,
                    evidence_snippet=f"lines={axfr.get('line_count')}",
                    fix="Disable AXFR to the public internet; allow only trusted secondaries.",
                    tags=["dns", "axfr"],
                )
            )

        dangling = []
        for prefix in ("staging", "dev", "uat", "test", "old", "legacy", "shop", "status"):
            cand = f"{prefix}.{apex}"
            cname = await dig_cname(cand)
            targets = cname.get("records") or []
            if not targets:
                continue
            # If CNAME target does not resolve → dangling hint
            for t in targets[:2]:
                t_host = t.rstrip(".")
                ips = resolve_public_ips(t_host)
                dns = await ctx.tools.dns_lookup(host=t_host)
                if not ips and not (dns.get("ok") and dns.get("addresses")):
                    dangling.append({"host": cand, "cname": t_host})
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"Possible dangling CNAME: {cand}",
                            evidence_url=ctx.url,
                            evidence_snippet=f"{cand} → {t_host} (no public A/AAAA)",
                            fix="Remove stale CNAMEs or claim the target service to prevent takeover.",
                            tags=["dns", "dangling"],
                        )
                    )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["dns_hygiene"] = {
            "axfr_refused": axfr.get("refused"),
            "open_axfr": axfr.get("open_axfr"),
            "dangling": dangling[:8],
        }
