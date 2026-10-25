from __future__ import annotations

import re
from typing import List, Optional, Tuple

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

EXPLAIN_SYSTEM = (
    "You are an application-security analyst writing for a product/engineering audience. "
    "For each finding, explain why it matters on THIS stack (use fingerprint/tags) "
    "and give a concrete remediation. "
    "Do not invent endpoints, status codes, or evidence. "
    "Do not change severity. Keep each WHY and FIX to 1–3 clear sentences. "
    "No markdown fences. No preamble."
)


def _pick_role(ctx: ScanContext) -> Optional[str]:
    if not ctx.llm:
        return None
    # Prefer reporter; fall back to adapt (often Gemini) when Claude/OpenAI unset
    for role in ("reporter", "adapt"):
        if ctx.llm.provider_name(role) != "null":  # type: ignore[arg-type]
            return role
    return None


def build_explain_prompt(ctx: ScanContext, findings: List[Finding]) -> str:
    lines = [
        f"Target: {ctx.url}",
        f"Fingerprint: {ctx.fingerprint}",
        "",
        "Write one block per finding using EXACTLY this format:",
        "N|WHY|<plain text>|FIX|<plain text>",
        "where N is the finding number below.",
        "",
        "Findings:",
    ]
    for i, f in enumerate(findings, 1):
        lines.extend(
            [
                f"{i}. [{f.severity.upper()}] ({f.agent}) {f.title}",
                f"   evidence_url: {f.evidence_url or '—'}",
                f"   evidence: {(f.evidence_snippet or '')[:320]}",
                f"   tags: {', '.join(f.tags) or '—'}",
                f"   stub_fix: {f.fix or '—'}",
                "",
            ]
        )
    return "\n".join(lines)


def parse_explain_lines(text: str, count: int) -> List[Tuple[str, str]]:
    """Return list of (why, fix) aligned to finding index 0..count-1."""
    out: List[Tuple[str, str]] = [("", "")] * count
    if not text:
        return out
    # N|WHY|...|FIX|...
    line_re = re.compile(
        r"""^\s*(\d+)\s*\|\s*WHY\s*\|\s*(.+?)\s*\|\s*FIX\s*\|\s*(.+?)\s*$""",
        re.I,
    )
    # Fallback: N. WHY: ... FIX: ...
    block_re = re.compile(
        r"""(?im)^\s*(\d+)[.)]\s*(?:WHY[:\s]+)(.+?)(?:\s+FIX[:\s]+)(.+?)(?=^\s*\d+[.)]|\Z)""",
        re.S,
    )
    matched = False
    for raw in text.splitlines():
        m = line_re.match(raw.strip())
        if not m:
            continue
        matched = True
        idx = int(m.group(1)) - 1
        if 0 <= idx < count:
            why = re.sub(r"\s+", " ", m.group(2)).strip().strip("|")
            fix = re.sub(r"\s+", " ", m.group(3)).strip().strip("|")
            if why or fix:
                out[idx] = (why[:600], fix[:600])
    if matched:
        return out
    for m in block_re.finditer(text.strip() + "\n"):
        idx = int(m.group(1)) - 1
        if 0 <= idx < count:
            why = re.sub(r"\s+", " ", m.group(2)).strip()
            fix = re.sub(r"\s+", " ", m.group(3)).strip()
            out[idx] = (why[:600], fix[:600])
    return out


async def enrich_findings_explanations(ctx: ScanContext) -> int:
    """LLM-write explanation + fix on actionable findings. Returns how many updated."""
    role = _pick_role(ctx)
    if not role:
        return 0
    actionable = [
        f
        for f in ctx.findings
        if f.severity in ("critical", "high", "medium") and f.agent != "reporter"
    ]
    if not actionable:
        return 0

    # Cap tokens: explain top 14 by severity order
    order = {"critical": 0, "high": 1, "medium": 2}
    actionable.sort(key=lambda f: order.get(f.severity, 9))
    batch = actionable[:14]

    prompt = build_explain_prompt(ctx, batch)
    try:
        text = await ctx.llm.complete(role, prompt, system=EXPLAIN_SYSTEM)  # type: ignore[arg-type]
    except Exception:
        text = ""
    parsed = parse_explain_lines(text or "", len(batch))
    updated = 0
    for f, (why, fix) in zip(batch, parsed):
        if why:
            f.explanation = why
            updated += 1
        if fix:
            f.fix = fix
            if not why:
                updated += 1
    return updated
