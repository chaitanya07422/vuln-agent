from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.safety import is_blocked_hostname, resolve_public_ips

RISKY = {21, 22, 23, 25, 445, 3306, 5432, 6379, 27017}
# 80/443 alone are normal for websites — never emit as a finding card


class PortsMailAgent(BaseAgent):
    name = "ports_mail"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = ctx.scope.host
        ctx.fingerprint = dict(ctx.fingerprint or {})

        if is_blocked_hostname(host) or not resolve_public_ips(host):
            ctx.fingerprint["ports_mail"] = {"skipped": True, "reason": "not publicly resolvable"}
            return

        dns = await ctx.tools.dns_lookup(host=host)
        await ctx.audit_event(agent=self.name, tool="dns_lookup", result=dns)
        addresses = dns.get("addresses") or [] if dns.get("ok") else []

        ports = await ctx.tools.port_probe(host=host)
        await ctx.audit_event(agent=self.name, tool="port_probe", result={"open": ports.get("open_ports")})
        open_ports = ports.get("open_ports") or []

        mx = await ctx.tools.mx_lookup(host=host)
        await ctx.audit_event(agent=self.name, tool="mx_lookup", result=mx)
        mail_hosts = []
        for mail_host in (mx.get("mail_hosts") or [])[:5]:
            if is_blocked_hostname(mail_host) or not resolve_public_ips(mail_host):
                continue
            # Skip noise: MX pointing at the same web host
            if mail_host.lower().rstrip(".") in {host.lower(), f"www.{host.lower()}"}:
                continue
            if host.lower().startswith("www.") and mail_host.lower().rstrip(".") == host.lower()[4:]:
                continue
            mail_hosts.append(mail_host)

        ctx.fingerprint["ports_mail"] = {
            "dns": addresses[:8],
            "open_ports": open_ports,
            "mail_hosts": mail_hosts[:3],
        }

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

        # Distinct mail hosts only (not www == site)
        for mail_host in mail_hosts[:2]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Separate mail host resolves: {mail_host}",
                    evidence_url=ctx.url,
                    evidence_snippet=mail_host,
                    tags=["mail"],
                )
            )
