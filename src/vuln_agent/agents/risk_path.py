from __future__ import annotations

from typing import List, Optional, Set

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

RISK_PATH_SYSTEM = (
    "You write a SHORT risk story for a non-technical business client. "
    "Describe how an outsider might abuse the combined findings at a high level. "
    "Rules (strict):\n"
    "- 3 to 5 numbered steps only\n"
    "- Each step one short sentence\n"
    "- No payloads, code, commands, headers, bypass tricks, tool names, or how-to detail\n"
    "- Only use risks that appear in the listed findings — never invent upload/XML-RPC/etc.\n"
    "- Adapt language to whatever stack/findings you see (any website)\n"
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


def _signals(f: Finding) -> Set[str]:
    blob = f"{f.agent} {f.title} {' '.join(f.tags or [])}".lower()
    out: Set[str] = set()
    checks = {
        "user_enum": ("user enumeration", "users?", "author", "enumerate"),
        "xmlrpc": ("xml-rpc", "xmlrpc"),
        "upload": ("upload", "presign", "request-url"),
        "mime": ("mime", "contenttype", "file.type", "accept="),
        "objects": ("object", "/objects/", "public html"),
        "resume": ("resumepath", "resume", "open-redirect", "phishing"),
        "auth_api": ("protected api", "auth required", "login"),
        "leak": ("exposed", ".env", "readme", "backup", "git"),
        "cors": ("cors", "origin"),
        "staging": ("staging", "uat", "test."),
    }
    for key, needles in checks.items():
        if any(n in blob for n in needles):
            out.add(key)
    return out


def _step_for(signal: str, n: int) -> Optional[str]:
    templates = {
        "user_enum": f"{n}. Someone can look up public account or author names from the site.",
        "xmlrpc": f"{n}. A remote login-style interface is reachable and can be pressed harder than a normal login page.",
        "upload": f"{n}. Someone targets the site’s file-upload flow (often after a normal login).",
        "mime": f"{n}. They may try a file type the browser allows but the business did not intend.",
        "objects": f"{n}. Uploaded content may be reachable via a public file link on the same site.",
        "resume": f"{n}. Stored profile/resume links may open whatever path was saved, which can trick staff.",
        "auth_api": f"{n}. Private API surfaces answer in a way that confirms they exist for a later attempt.",
        "leak": f"{n}. Leftover public files or configs can reveal software details useful for planning.",
        "cors": f"{n}. Browser cross-origin rules may be too open for sensitive APIs.",
        "staging": f"{n}. A non-production host linked from the live site widens the attack surface.",
    }
    return templates.get(signal)


def _priority_for(signals: Set[str], findings: List[Finding]) -> str:
    if "upload" in signals or "mime" in signals or "objects" in signals or "resume" in signals:
        return "harden upload handling and how files/links are opened first"
    if "user_enum" in signals or "xmlrpc" in signals:
        return "lock down public user listing and unused remote-login interfaces first"
    if "leak" in signals:
        return "remove exposed config/docs files from production first"
    if "cors" in signals:
        return "tighten CORS on sensitive APIs first"
    if "staging" in signals:
        return "remove or lock staging links from production first"
    top = sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 9))
    if top:
        return f"address this first: {top[0].title[:80]}"
    return "fix the highest-severity finding first"


def heuristic_risk_path(ctx: ScanContext) -> str:
    """Build a short story only from signals present in findings — adaptable to any site."""
    findings = _actionable(ctx)
    if not findings:
        return (
            "No medium-or-higher issues were confirmed in this pass. "
            "Keep monitoring after releases."
        )

    ordered_signals: List[str] = []
    seen: Set[str] = set()
    # Preserve finding priority order so the story follows what we actually found
    for f in sorted(
        findings,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x.severity, 9),
    ):
        for sig in _signals(f):
            if sig not in seen:
                seen.add(sig)
                ordered_signals.append(sig)

    steps: List[str] = []
    n = 1
    for sig in ordered_signals:
        line = _step_for(sig, n)
        if line:
            steps.append(line)
            n += 1
        if len(steps) >= 4:
            break

    if not steps:
        steps.append(f"1. An outsider focuses on the exposed surfaces listed in the priority findings.")
        steps.append(f"2. Weak checks on those surfaces could expose data or actions meant for staff only.")
    elif len(steps) == 1:
        steps.append(f"{n}. That exposure can help them plan follow-up attempts against staff or data.")

    priority = _priority_for(seen, findings)
    # De-dupe identical lines
    uniq: List[str] = []
    seen_lines: Set[str] = set()
    for s in steps:
        key = s.lower()
        if key in seen_lines:
            continue
        seen_lines.add(key)
        uniq.append(s)
    return "\n".join(uniq[:5] + [f"Priority fix: {priority}."])


def _clean_path(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    kept = []
    seen = set()
    for ln in lines:
        if ln.startswith("```"):
            continue
        if ln.lower().startswith("#"):
            ln = ln.lstrip("#").strip()
        key = ln.lower()
        if key in seen:
            continue
        seen.add(key)
        kept.append(ln)
    return "\n".join(kept[:8]).strip()[:1200]


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
        "Write the brief risk path now. Only use the findings above."
    )
    try:
        text = await ctx.llm.complete(role, prompt, system=RISK_PATH_SYSTEM)  # type: ignore[arg-type]
    except Exception:
        text = ""
    cleaned = _clean_path(text or "")
    if cleaned.count("\n") >= 2 and any(ch.isdigit() for ch in cleaned[:80]):
        if "priority fix" not in cleaned.lower():
            cleaned = (
                cleaned.rstrip(".")
                + "\nPriority fix: address the highest-severity finding in this list first."
            )
        return cleaned
    return fallback
