from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLMCallUsage:
    provider: str
    model: str
    role: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    ok: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def estimate_tokens(text: str) -> int:
    """Rough fallback when provider omits usage (~4 chars/token)."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def summarize_usage(calls: List[LLMCallUsage]) -> Dict[str, Any]:
    by_role: Dict[str, Dict[str, int]] = {}
    by_model: Dict[str, Dict[str, int]] = {}
    total = 0
    for c in calls:
        total += int(c.total_tokens or 0)
        role = c.role or "unknown"
        model = c.model or c.provider or "unknown"
        by_role.setdefault(role, {"calls": 0, "total_tokens": 0})
        by_role[role]["calls"] += 1
        by_role[role]["total_tokens"] += int(c.total_tokens or 0)
        by_model.setdefault(model, {"calls": 0, "total_tokens": 0})
        by_model[model]["calls"] += 1
        by_model[model]["total_tokens"] += int(c.total_tokens or 0)
    return {
        "calls": [c.to_dict() for c in calls],
        "call_count": len(calls),
        "total_tokens": total,
        "by_role": by_role,
        "by_model": by_model,
    }
