from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from vuln_agent.agents.summary import AGENT_LABELS


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initial_agents_progress(enabled_agents: Sequence[str]) -> List[Dict[str, Any]]:
    """Build pending rows for every enabled agent (reporter included for live UI)."""
    rows: List[Dict[str, Any]] = []
    for name in enabled_agents:
        rows.append(
            {
                "agent": name,
                "label": AGENT_LABELS.get(name, name.replace("_", " ").title()),
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "detail": None,
                "step_at": None,
            }
        )
    return rows


def set_agent_status(
    progress: List[Dict[str, Any]],
    agent_name: str,
    status: str,
) -> List[Dict[str, Any]]:
    """Return a new progress list with one agent's status updated."""
    now = _utc_now()
    out: List[Dict[str, Any]] = []
    for row in progress:
        if row.get("agent") != agent_name:
            out.append(dict(row))
            continue
        updated = dict(row)
        updated["status"] = status
        if status == "running" and not updated.get("started_at"):
            updated["started_at"] = now
            if not updated.get("detail"):
                updated["detail"] = "starting…"
                updated["step_at"] = now
        if status in ("done", "skipped", "failed"):
            updated["finished_at"] = now
            if not updated.get("started_at"):
                updated["started_at"] = now
            if status == "skipped" and not updated.get("detail"):
                updated["detail"] = "skipped (stack tags)"
            if status == "done" and not updated.get("detail"):
                updated["detail"] = "cleared"
        out.append(updated)
    return out


def set_agent_detail(
    progress: List[Dict[str, Any]],
    agent_name: str,
    detail: str,
) -> List[Dict[str, Any]]:
    """Attach the latest live step line for an agent (URL/path/tool)."""
    now = _utc_now()
    text = (detail or "").strip()[:180]
    if not text:
        return progress
    out: List[Dict[str, Any]] = []
    for row in progress:
        if row.get("agent") != agent_name:
            out.append(dict(row))
            continue
        updated = dict(row)
        updated["detail"] = text
        updated["step_at"] = now
        out.append(updated)
    return out


def format_audit_detail(**payload: Any) -> str:
    """Turn an audit_event payload into a short UI step line."""
    from urllib.parse import urlparse

    tool = str(payload.get("tool") or "probe")
    url = payload.get("url")
    phase = payload.get("phase")
    path = payload.get("path")
    msg = payload.get("msg") or payload.get("message") or payload.get("detail")

    if url:
        try:
            parsed = urlparse(str(url))
            shown = parsed.path or "/"
            if parsed.query:
                shown = f"{shown}?{parsed.query[:48]}"
            if parsed.hostname and parsed.hostname not in shown:
                # cross-host probes (CDN, buckets) — keep host
                shown = f"{parsed.hostname}{shown}"
        except Exception:
            shown = str(url)[:100]
    elif path:
        shown = str(path)[:100]
    elif msg:
        shown = str(msg)[:120]
    else:
        bits = []
        for key in ("selector", "host", "record", "finding", "result"):
            if payload.get(key) is not None:
                bits.append(f"{key}={payload[key]}")
        shown = ", ".join(bits)[:120] if bits else tool

    if phase == "start":
        return f"{tool} → {shown}"
    ok = payload.get("ok")
    if ok is True:
        return f"{tool} {shown} · ok"
    if ok is False:
        return f"{tool} {shown} · miss"
    return f"{tool} {shown}"
