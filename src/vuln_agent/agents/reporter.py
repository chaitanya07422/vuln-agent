from __future__ import annotations

from collections import Counter
from typing import List

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.dedupe import dedupe_findings
from vuln_agent.agents.explain import enrich_findings_explanations
from vuln_agent.agents.risk_path import build_risk_path
from vuln_agent.agents.summary import build_scan_summary, strip_noise_findings
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.llm.prompts import REPORTER_SYSTEM, format_reporter_user


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_company_brief(ctx: ScanContext) -> str:
    findings: List[Finding] = list(ctx.findings)
    by_sev = Counter(f.severity for f in findings)
    summary = ctx.summary or {}
    lines = [
        f"# Security brief — {ctx.url}",
        "",
        "## Executive summary",
        "",
        summary.get("headline")
        or (
            f"Scan `{ctx.scan_id}` finished with **{len(findings)}** findings "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})."
        ),
        "",
        f"**Stack:** `{summary.get('stack') or ctx.fingerprint}`",
        "",
    ]
    if summary.get("agents"):
        lines.extend(["## What each agent checked", ""])
        for row in summary["agents"]:
            mark = "Needs attention" if row.get("status") == "attention" else "Clear"
            lines.append(f"- **{row.get('label')}** — {mark}: {row.get('note')}")
        lines.append("")

    if summary.get("all_clear"):
        lines.extend(
            [
                "## Overall",
                "",
                "Everything checked looks solid for this detect-only pass.",
                "",
            ]
        )
    elif ctx.risk_path:
        lines.extend(
            [
                "## How this could be abused (high level)",
                "",
                "For client understanding only — not an exploit guide.",
                "",
                ctx.risk_path,
                "",
            ]
        )

    lines.extend(["## Priority findings", ""])
    actionable = [f for f in findings if f.severity in ("critical", "high", "medium")]
    actionable.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    if not actionable:
        if findings:
            lines.append("No critical/high/medium issues; see low-severity notes below if any.")
        else:
            lines.append("No issues to list.")
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
                    f"- Why it matters: {f.explanation or 'See evidence and remediation below.'}",
                    f"- Fix: {f.fix or 'Review and harden this surface.'}",
                    "",
                ]
            )

    lows = [f for f in findings if f.severity == "low"]
    if lows:
        lines.extend(["## Minor hygiene", ""])
        for f in lows:
            lines.append(f"- {f.title} — {f.fix or 'Optional cleanup.'}")
        lines.append("")

    lines.extend(["## Retest checklist", ""])
    for f in actionable:
        lines.append(f"- [ ] Re-check: {f.title} ({f.evidence_url or 'n/a'})")
    if not actionable:
        lines.append("- [ ] Re-run scan after stack changes")
    lines.append("")
    return "\n".join(lines)


class ReporterAgent(BaseAgent):
    name = "reporter"
    requires_tags: list = []
    skip_if_tags: list = []

    async def run(self, ctx: ScanContext) -> None:
        before = len(ctx.findings)
        ctx.findings = dedupe_findings(list(ctx.findings))
        ctx.findings = strip_noise_findings(ctx.findings)
        dropped = before - len(ctx.findings)

        enriched = await enrich_findings_explanations(ctx)

        enabled = []
        try:
            # settings not on ctx — infer from fingerprint + findings + common set
            from vuln_agent.settings import Settings

            enabled = list(Settings.load().enabled_agents)
        except Exception:
            enabled = []

        ctx.summary = build_scan_summary(ctx, enabled_agents=enabled)
        if ctx.summary.get("all_clear"):
            ctx.risk_path = None
        else:
            ctx.risk_path = await build_risk_path(ctx)

        brief = build_company_brief(ctx)

        role = None
        if ctx.llm:
            for candidate in ("reporter", "adapt"):
                if ctx.llm.provider_name(candidate) != "null":
                    role = candidate
                    break
        if role:
            polished = await ctx.llm.complete(
                role,  # type: ignore[arg-type]
                format_reporter_user(brief=brief),
                system=REPORTER_SYSTEM,
            )
            if polished and polished.strip().startswith("#"):
                brief = polished.strip()
            elif polished and len(polished.strip()) > 80:
                brief = brief + "\n## Analyst notes\n\n" + polished.strip() + "\n"

        ctx.report_md = brief
        llm_name = ctx.llm.provider_name(role) if ctx.llm and role else "null"  # type: ignore[arg-type]
        await ctx.audit_event(
            agent=self.name,
            tool="report",
            findings=len(ctx.findings),
            deduped=dropped,
            explained=enriched,
            verdict=(ctx.summary or {}).get("verdict"),
            llm=llm_name,
        )
