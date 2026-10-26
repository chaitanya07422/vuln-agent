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
        if status in ("done", "skipped", "failed"):
            updated["finished_at"] = now
            if not updated.get("started_at"):
                updated["started_at"] = now
        out.append(updated)
    return out
