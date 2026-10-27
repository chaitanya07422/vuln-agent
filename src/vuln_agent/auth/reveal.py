from __future__ import annotations

from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def choose_detail_level(
    *,
    plan: str,
    owner_scan_count: Optional[int] = None,
    guest_used_before: Optional[int] = None,
    free_full_limit: int = 2,
    guest_full_limit: int = 1,
) -> str:
    """Pick full vs teaser at scan create time."""
    if plan == "pro":
        return "full"
    if owner_scan_count is not None:
        return "full" if owner_scan_count < free_full_limit else "teaser"
    used = int(guest_used_before or 0)
    return "full" if used < guest_full_limit else "teaser"


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(str(f.get("severity") or "info"), 9),
    )


def apply_reveal(
    scan: Dict[str, Any],
    *,
    viewer: Optional[Dict[str, Any]] = None,
    force_full: bool = False,
) -> Dict[str, Any]:
    """
    Redact scan payload for freemium teaser views.
    Pro owners always see full. Stored detail_level otherwise.
    """
    out = dict(scan)
    level = "full" if force_full else (out.get("detail_level") or "full")

    if viewer and viewer.get("id") and viewer.get("id") == out.get("owner_id"):
        plan = (viewer.get("plan") or "free").lower()
        # Pro always full; deep-brief unlock / branded purchase also unlocks.
        if plan == "pro" or out.get("unlocked_full") or out.get("branded_brief"):
            level = "full"

    out["detail_level"] = level
    findings = list(out.get("findings") or [])
    actionable = [
        f
        for f in findings
        if str(f.get("severity") or "") != "info" and str(f.get("agent") or "") != "reporter"
    ]
    total = len(actionable) if actionable else len(findings)
    out["findings_total"] = total

    if level == "full":
        out["hidden_findings"] = 0
        return out

    ranked = _sort_findings(actionable or findings)
    kept = ranked[:1]
    out["findings"] = kept
    out["hidden_findings"] = max(0, total - len(kept))
    out["risk_path"] = None
    # Keep a short summary headline; strip per-agent notes that leak detail.
    summary = dict(out.get("summary") or {})
    if summary:
        summary["agents"] = []
        summary["attention"] = []
        summary["clean"] = []
        if out["hidden_findings"]:
            summary["headline"] = (
                summary.get("headline")
                or f"{total} signal{'s' if total != 1 else ''} found — sign in / upgrade to unlock."
            )
        out["summary"] = summary
    fp = dict(out.get("fingerprint") or {})
    for key in ("executive_brief", "llm_usage", "js_api_paths"):
        fp.pop(key, None)
    out["fingerprint"] = fp
    return out


def teaser_report_md(scan: Dict[str, Any]) -> str:
    findings = scan.get("findings") or []
    hidden = int(scan.get("hidden_findings") or 0)
    total = int(scan.get("findings_total") or (len(findings) + hidden))
    lines = [
        f"# Security brief — {scan.get('url')}",
        "",
        "## Locked preview",
        "",
        f"This scan found **{total}** signal{'s' if total != 1 else ''}.",
        "Free / guest preview shows **1** finding. Sign in for 2 full Free briefs, or upgrade to Pro to unlock everything.",
        "",
    ]
    if findings:
        f = findings[0]
        lines.extend(
            [
                "## Preview finding",
                "",
                f"- **[{str(f.get('severity') or '').upper()}]** {f.get('title')}",
                f"- Agent: `{f.get('agent')}`",
                "",
            ]
        )
    if hidden:
        lines.append(f"_Plus {hidden} more finding{'s' if hidden != 1 else ''} hidden._")
        lines.append("")
    return "\n".join(lines)
