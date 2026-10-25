from __future__ import annotations

from typing import List, Optional

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

RISK_PATH_SYSTEM = (
    "You write a SHORT risk story for a non-technical business client. "
    "Describe how an outsider might abuse the combined findings at a high level. "
    "Rules (strict):\n"
    "- 3 to 5 numbered steps only\n"
    "- Each step one short sentence\n"
    "- No payloads, code, commands, headers, bypass tricks, tool names, or how-to detail\n"
    "- No inventing findings that are not listed\n"
    "- Use plain business language (account, resume file, public link, login)\n"
    "- End with one line: 'Priority fix:' naming the first control to harden\n"
    "This must help the client understand impact — not help an attacker operate."
)


def _pick_role(ctx: ScanContext) -> Optional[str]:
    if not ctx.llm:
        return None
    for role in ("reporter", "adapt"):
        if ctx.llm.provider_name(role) != "null":  # type: ignore[arg-type]
            return role
    return None


def _actionable(ctx: ScanContext) -> List[Finding]:
    return [
        f
        for f in ctx.findings
        if f.severity in ("critical", "high", "medium") and f.agent != "reporter"
    ]


def heuristic_risk_path(ctx: ScanContext) -> str:
    findings = _actionable(ctx)
    if not findings:
        return (
            "No medium-or-higher issues were confirmed in this pass. "
            "Keep monitoring after releases."
        )
    tags = {t for f in findings for t in (f.tags or [])}
    titles = " ".join(f.title.lower() for f in findings)
    steps: List[str] = []
    n = 1
    if "upload" in tags or "presign" in tags or "upload" in titles:
        steps.append(f"{n}. Someone targets the site’s file-upload flow (often after a normal login).")
        n += 1
    if "mime" in tags or "client-validation" in tags or "contenttype" in titles or "mime" in titles:
        steps.append(f"{n}. They try to send a file type the browser allows but the business did not intend.")
        n += 1
    if "objects" in tags or "object" in titles or "/objects/" in titles:
        steps.append(f"{n}. Uploaded content may be reachable via a public object/file link on the same site.")
        n += 1
    if "resumepath" in tags or "resume" in titles or "open-redirect" in tags or "phishing" in tags:
        steps.append(
            f"{n}. If resume/profile links open whatever path is stored, that can trick staff into opening a bad link."
        )
        n += 1
    if not steps:
        steps.append(f"{n}. An outsider focuses on the exposed surfaces listed in the priority findings.")
        n += 1
        steps.append(f"{n}. Misconfiguration or weak checks could let them reach data or actions meant for staff only.")
    while len(steps) < 3 and n <= 5:
        steps.append(f"{n}. Defenders should treat the listed findings as one chain, not isolated tickets.")
        n += 1
    priority = "review upload and public file links first" if ("upload" in tags or "upload" in titles) else "fix the highest-severity finding first"
    return "\n".join(steps + [f"Priority fix: {priority}."])


def _clean_path(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    # Drop markdown fences / headings the model sometimes adds
    kept = []
    for ln in lines:
        if ln.startswith("```"):
            continue
        if ln.lower().startswith("#"):
            ln = ln.lstrip("#").strip()
        kept.append(ln)
    # Cap length — client brief, not a handbook
    kept = kept[:8]
    body = "\n".join(kept).strip()
    return body[:1200]


async def build_risk_path(ctx: ScanContext) -> str:
    """Brief client-facing abuse narrative from all priority findings."""
    findings = _actionable(ctx)
    fallback = heuristic_risk_path(ctx)
    role = _pick_role(ctx)
    if not role or not findings:
        return fallback

    bullets = []
    for f in findings[:12]:
        bullets.append(
            f"- [{f.severity}] ({f.agent}) {f.title} | evidence={(f.evidence_snippet or '')[:120]}"
        )
    prompt = (
        f"Site: {ctx.url}\n"
        f"Stack hints: {ctx.fingerprint}\n"
        f"Priority findings:\n" + "\n".join(bullets) + "\n\n"
        "Write the brief risk path now."
    )
    try:
        text = await ctx.llm.complete(role, prompt, system=RISK_PATH_SYSTEM)  # type: ignore[arg-type]
    except Exception:
        text = ""
    cleaned = _clean_path(text or "")
    # Require numbered steps; else heuristic
    if cleaned.count("\n") >= 2 and any(ch.isdigit() for ch in cleaned[:80]):
        if "priority fix" not in cleaned.lower():
            cleaned = cleaned.rstrip(".") + "\nPriority fix: address the highest-severity finding in this list first."
        return cleaned
    return fallback
