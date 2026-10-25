from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.safety import is_blocked_hostname, resolve_public_ips

RISKY = {21, 22, 23, 25, 445, 3306, 5432, 6379, 27017}


class PortsMailAgent(BaseAgent):
    name = "ports_mail"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host
        if is_blocked_hostname(host) or not resolve_public_ips(host):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="Port/mail checks skipped — host not publicly resolvable",
                    evidence_url=ctx.url,
                    evidence_snippet=host,
                    tags=["dns", "skipped"],
                )
            )
            return

        dns = await ctx.tools.dns_lookup(host=host)
        await ctx.audit_event(agent=self.name, tool="dns_lookup", result=dns)
        if dns.get("ok") and dns.get("addresses"):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"DNS resolves {host}",
                    evidence_url=ctx.url,
                    evidence_snippet=", ".join(dns["addresses"][:8]),
                    tags=["dns"],
                )
            )

        ports = await ctx.tools.port_probe(host=host)
        await ctx.audit_event(agent=self.name, tool="port_probe", result={"open": ports.get("open_ports")})
        open_ports = ports.get("open_ports") or []
        if open_ports:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Open ports: {open_ports}",
                    evidence_url=ctx.url,
                    evidence_snippet=str(open_ports),
                    tags=["ports"],
                )
            )
        for p in open_ports:
            if p in RISKY:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium" if p not in (22, 25) else "low",
                        title=f"Sensitive service port open: {p}",
                        evidence_url=ctx.url,
                        evidence_snippet=f"TCP {p} accepted a connection",
                        fix="Restrict management/DB/mail ports to private networks.",
                        tags=["ports", "exposure"],
                    )
                )

        if 25 in open_ports:
            banner = await ctx.tools.smtp_banner(host=host, port=25)
            await ctx.audit_event(agent=self.name, tool="smtp_banner", result=banner)
            if banner.get("ok") and banner.get("banner"):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title="SMTP banner exposed",
                        evidence_url=ctx.url,
                        evidence_snippet=banner["banner"],
                        fix="Limit public SMTP; avoid leaking software versions in banners.",
                        tags=["mail", "smtp"],
                    )
                )

        mx = await ctx.tools.mx_lookup(host=host)
        await ctx.audit_event(agent=self.name, tool="mx_lookup", result=mx)
        for mail_host in (mx.get("mail_hosts") or [])[:2]:
            if is_blocked_hostname(mail_host) or not resolve_public_ips(mail_host):
                continue
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Mail-related host resolves: {mail_host}",
                    evidence_url=ctx.url,
                    evidence_snippet=mail_host,
                    tags=["mail"],
                )
            )
