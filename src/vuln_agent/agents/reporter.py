from __future__ import annotations

from collections import Counter
from typing import List

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_company_brief(ctx: ScanContext) -> str:
    findings: List[Finding] = list(ctx.findings)
    by_sev = Counter(f.severity for f in findings)
    lines = [
        f"# Security brief — {ctx.url}",
        "",
        "## Executive summary",
        "",
        f"Scan `{ctx.scan_id}` finished with **{len(findings)}** findings "
        f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
        f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)}, info={by_sev.get('info', 0)}).",
        "",
        f"**Fingerprint:** `{ctx.fingerprint}`",
        "",
        "## Priority findings",
        "",
    ]
    actionable = [f for f in findings if f.severity in ("critical", "high", "medium")]
    actionable.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    if not actionable:
        lines.append("No critical/high/medium issues detected by enabled agents.")
        lines.append("")
    else:
        for i, f in enumerate(actionable, 1):
            lines.extend(
                [
                    f"### {i}. [{f.severity.upper()}] {f.title}",
                    "",
                    f"- Agent: `{f.agent}`",
                    f"- Evidence: {f.evidence_url or '—'}",
                    f"- Detail: `{f.evidence_snippet or ''}`",
                    f"- Fix: {f.fix or 'Review and harden this surface.'}",
                    "",
                ]
            )

    lines.extend(["## Retest checklist", ""])
    for f in actionable:
        lines.append(f"- [ ] Re-check: {f.title} ({f.evidence_url or 'n/a'})")
    if not actionable:
        lines.append("- [ ] Re-run scan after stack changes")
    lines.append("")
    lines.extend(["## All findings", ""])
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        lines.append(f"- **{f.severity.upper()}** ({f.agent}) {f.title}")
    lines.append("")
    return "\n".join(lines)


class ReporterAgent(BaseAgent):
    name = "reporter"
    requires_tags: list = []
    skip_if_tags: list = []

    async def run(self, ctx: ScanContext) -> None:
        brief = build_company_brief(ctx)
        if ctx.llm and ctx.llm.provider_name("reporter") != "null":
            polished = await ctx.llm.complete(
                "reporter",
                (
                    "Polish this authorized security brief for a company audience. "
                    "Keep ALL findings, severities, evidence URLs, and fixes exactly — "
                    "do not drop js_audit/upload chain findings. "
                    "Call out chained risks (upload → public object HTML → resumePath) in the executive summary if present. "
                    "Return markdown only.\n\n" + brief
                ),
                system=(
                    "You are a concise application-security writer. "
                    "Never invent findings. Prefer clear remediation over hype."
                ),
            )
            if polished and polished.strip().startswith("#"):
                brief = polished.strip()
            elif polished and len(polished.strip()) > 80:
                # LLM returned prose without heading — keep structured brief, append note
                brief = brief + "\n## Analyst notes\n\n" + polished.strip() + "\n"

        ctx.report_md = brief
        await ctx.emit_finding(
            Finding(
                agent=self.name,
                severity="info",
                title="Report generated",
                evidence_url=ctx.url,
                evidence_snippet=(
                    f"{len(ctx.findings)} findings; llm={ctx.llm.provider_name('reporter') if ctx.llm else 'null'}"
                ),
                tags=["report"],
            )
        )
