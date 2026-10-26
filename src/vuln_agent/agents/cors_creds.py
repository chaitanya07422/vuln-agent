from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: ACAO + credentials combo (extends cors_api). No credential theft.


class CorsCredsAgent(BaseAgent):
    name = "cors_creds"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        evil = "https://evil.scanlead-check.invalid"
        resp = await ctx.tools.http_request(
            method="GET",
            url=ctx.url,
            headers={"Origin": evil},
            max_body_bytes=8000,
        )
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        acao = headers.get("access-control-allow-origin") or ""
        acac = (headers.get("access-control-allow-credentials") or "").lower()
        reflect = acao == evil or acao == "*"
        creds = acac == "true"

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cors_creds"] = {"acao": acao, "acac": acac}

        if reflect and creds and acao == "*":
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="CORS allows credentials with wildcard origin (invalid/dangerous)",
                    evidence_url=ctx.url,
                    evidence_snippet=f"ACAO={acao} ACAC={acac}",
                    fix="Never combine Access-Control-Allow-Credentials: true with ACAO *.",
                    tags=["cors", "credentials"],
                )
            )
        elif acao == evil and creds:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="CORS reflects arbitrary Origin with credentials",
                    evidence_url=ctx.url,
                    evidence_snippet=f"ACAO={acao} ACAC={acac}",
                    fix="Allowlist trusted origins; do not echo Origin when credentials are allowed.",
                    tags=["cors", "credentials"],
                )
            )
        elif acao == evil and not creds:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="CORS reflects arbitrary Origin",
                    evidence_url=ctx.url,
                    evidence_snippet=f"ACAO={acao}",
                    fix="Allowlist trusted origins instead of reflecting the request Origin.",
                    tags=["cors"],
                )
            )
        elif acao == "*" and not creds:
            # Often intentional for public APIs — low note only
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="CORS Access-Control-Allow-Origin is *",
                    evidence_url=ctx.url,
                    evidence_snippet="ACAO=*",
                    tags=["cors"],
                )
            )
