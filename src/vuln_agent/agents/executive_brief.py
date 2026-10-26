from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.summary import strip_noise_findings
from vuln_agent.core.context import ScanContext

# Report-layer: short C-level blurb via existing LLM path (rate-limited). Detect-only text.


EXEC_SYSTEM = (
    "You write a 3–5 sentence executive security brief for ScanLead. "
    "Audience: CEO/CFO. No exploit steps. Do not invent findings. "
    "If the site looks solid, say so plainly. Output plain text only."
)


class ExecutiveBriefAgent(BaseAgent):
    name = "executive_brief"
    requires_tags: list = []
    skip_if_tags: list = []

    async def run(self, ctx: ScanContext) -> None:
        findings = strip_noise_findings(list(ctx.findings))
        actionable = [f for f in findings if f.severity in ("critical", "high", "medium", "low")]
        tops = sorted(
            actionable,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
        )[:8]
        lines = [
            f"Target: {ctx.url}",
            f"Stack: {(ctx.fingerprint or {}).get('tags')}",
            f"Issue count: {len(actionable)}",
        ]
        for f in tops:
            lines.append(f"- [{f.severity}] {f.title}")
        owasp = (ctx.fingerprint or {}).get("owasp_attention") or []
        if owasp:
            lines.append("OWASP themes: " + ", ".join(owasp))

        brief = ""
        if ctx.llm and ctx.llm.provider_name("reporter") != "null" and tops:
            try:
                brief = await ctx.llm.complete(
                    "reporter",
                    "\n".join(lines),
                    system=EXEC_SYSTEM,
                )
            except Exception:
                brief = ""
        if not brief:
            if not actionable:
                brief = (
                    f"External detect-only checks against {ctx.url} did not surface "
                    "critical, high, medium, or low issues in this pass. "
                    "Continue routine hygiene and re-scan after major releases."
                )
            else:
                titles = "; ".join(t.title for t in tops[:3])
                brief = (
                    f"ScanLead’s detect-only pass on {ctx.url} found {len(actionable)} "
                    f"issue(s) worth attention. Top themes: {titles}. "
                    "Engineering should remediate priority items and re-scan."
                )

        brief = (brief or "").strip()[:1200]
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["executive_brief"] = brief
        # Prefer injecting into company brief via fingerprint; reporter reads headline
        if ctx.summary is None:
            ctx.summary = {}
