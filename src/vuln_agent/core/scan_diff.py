from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple


def _key(f: Dict[str, Any]) -> str:
    return f"{f.get('agent')}|{(f.get('title') or '').strip().lower()}"


def diff_findings(
    previous: List[Dict[str, Any]],
    current: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare actionable findings between two scans."""

    def actionable(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            f
            for f in items
            if f.get("severity") in ("critical", "high", "medium", "low")
            and f.get("agent") != "reporter"
        ]

    prev = actionable(previous)
    curr = actionable(current)
    prev_map = {_key(f): f for f in prev}
    curr_map = {_key(f): f for f in curr}
    prev_keys: Set[str] = set(prev_map)
    curr_keys: Set[str] = set(curr_map)

    new_keys = curr_keys - prev_keys
    fixed_keys = prev_keys - curr_keys
    still_keys = curr_keys & prev_keys

    def brief(f: Dict[str, Any]) -> Dict[str, str]:
        return {
            "agent": str(f.get("agent") or ""),
            "severity": str(f.get("severity") or ""),
            "title": str(f.get("title") or ""),
        }

    return {
        "new": [brief(curr_map[k]) for k in sorted(new_keys)],
        "fixed": [brief(prev_map[k]) for k in sorted(fixed_keys)],
        "still_open": [brief(curr_map[k]) for k in sorted(still_keys)],
        "counts": {
            "new": len(new_keys),
            "fixed": len(fixed_keys),
            "still_open": len(still_keys),
        },
    }
