from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Friendly labels for the client summary
AGENT_LABELS = {
    "recon": "Recon & fingerprint",
    "js_audit": "Frontend JS review",
    "users": "User / author exposure",
    "auth": "Auth surfaces",
    "leaks": "Leaks & leftover files",
    "cors_api": "CORS & public APIs",
    "upload": "Upload & file routes",
    "uat_app": "Staging / UAT links",
    "ports_mail": "Ports & mail",
    "adapt": "Extra path probes",
    "reporter": "Report",
}

# Routine noise — never show as finding cards
NOISE_TITLE_PREFIXES = (
    "recon complete",
    "server header exposed",
    "tech fingerprint",
    "dns resolves",
    "open ports:",
    "mail-related host resolves",
    "report generated",
    "wordpress license.txt",
    "unknown stack",
)


def is_noise_finding(f: Finding) -> bool:
    """Info-only chatter belongs in the summary, not finding cards."""
    if f.agent == "reporter":
        return True
    if f.severity == "info":
        return True
    title = (f.title or "").lower()
    if any(title.startswith(p) or p in title for p in NOISE_TITLE_PREFIXES):
        return True
    return False


def strip_noise_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not is_noise_finding(f)]


def _agent_issue_line(findings: List[Finding]) -> str:
    tops = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
    )
    titles = [t.title for t in tops[:2]]
    return "; ".join(titles)


def build_scan_summary(ctx: ScanContext, enabled_agents: List[str] | None = None) -> Dict[str, Any]:
    """
    Comprehensive per-agent rollup for the UI.
    'looks_solid' only when there are zero critical/high/medium/low findings after noise strip.
    """
    findings = strip_noise_findings(list(ctx.findings))
    by_agent: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_agent[f.agent].append(f)

    actionable = [f for f in findings if f.severity in ("critical", "high", "medium")]
    lows = [f for f in findings if f.severity == "low"]
    agents_run: List[str] = list(enabled_agents or [])
    if not agents_run:
        agents_run = sorted({f.agent for f in ctx.findings} | set(by_agent.keys()))
    agents_run = [a for a in agents_run if a != "reporter"]

    fp = ctx.fingerprint or {}
    tags = list(fp.get("tags") or [])
    stack = ", ".join(tags) if tags else "unknown"

    rows: List[Dict[str, str]] = []
    clean: List[str] = []
    attention: List[str] = []

    for name in agents_run:
        label = AGENT_LABELS.get(name, name)
        items = by_agent.get(name) or []
        issues = [f for f in items if f.severity in ("critical", "high", "medium", "low")]
        if issues:
            status = "attention"
            note = _agent_issue_line(issues)
            attention.append(f"{label}: {note}")
        else:
            status = "clear"
            note = _clear_note(name, fp, tags)
            clean.append(f"{label}: {note}")
        rows.append({"agent": name, "label": label, "status": status, "note": note})

    if actionable:
        verdict = "issues_found"
        headline = (
            f"Scan finished with {len(actionable)} priority issue"
            f"{'s' if len(actionable) != 1 else ''} that need attention."
        )
        all_clear = False
    elif lows:
        verdict = "minor_notes"
        headline = (
            "No major vulnerabilities in this pass; "
            f"{len(lows)} minor hygiene note{'s' if len(lows) != 1 else ''} remain."
        )
        all_clear = False
    else:
        # Only then — user asked for 100% clear bar
        verdict = "looks_solid"
        headline = (
            "Everything checked looks solid — no critical, high, medium, or low "
            "issues in this detect-only pass."
        )
        all_clear = True

    return {
        "verdict": verdict,
        "headline": headline,
        "all_clear": all_clear,
        "stack": stack,
        "agents": rows,
        "clean": clean,
        "attention": attention,
        "priority_count": len(actionable),
        "low_count": len(lows),
    }


def _clear_note(agent: str, fp: dict, tags: list) -> str:
    if agent == "recon":
        title = fp.get("title") or "site reachable"
        return f"Reachable; stack={', '.join(tags) or 'unknown'}; page={str(title)[:60]}"
    if agent == "js_audit":
        n = len(fp.get("js_api_paths") or [])
        return f"JS reviewed; no risky patterns flagged ({n} API paths noted)" if n else "JS reviewed; no risky patterns flagged"
    if agent == "upload":
        return "No confirmed upload/presign JSON API or unsafe object HTML"
    if agent == "users":
        return "No public user enumeration detected"
    if agent == "auth":
        return "No risky auth surfaces flagged"
    if agent == "leaks":
        return "No sensitive leaks confirmed"
    if agent == "cors_api":
        return "No CORS misconfig / open API docs flagged"
    if agent == "uat_app":
        return "No staging hosts linked from production"
    if agent == "ports_mail":
        return "No risky management/DB ports exposed (80/443 only is normal)"
    if agent == "adapt":
        return "Extra probes found nothing beyond expected auth walls"
    return "No issues flagged"
