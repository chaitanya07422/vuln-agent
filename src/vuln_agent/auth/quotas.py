from __future__ import annotations

from typing import Any, Dict, Optional

from vuln_agent.auth.deps import effective_plan

# Saved-history caps for authenticated users
HISTORY_LIMITS = {"free": 10, "pro": 500, "anon": 0}
# Soft monthly create caps when logged in (anon unlimited but no save)
CREATE_LIMITS = {"free": 30, "pro": 300, "anon": 9999}


def history_limit(user: Optional[Dict[str, Any]]) -> int:
    return HISTORY_LIMITS.get(effective_plan(user), 10)


def create_limit(user: Optional[Dict[str, Any]]) -> int:
    return CREATE_LIMITS.get(effective_plan(user), 30)


def is_pro(user: Optional[Dict[str, Any]]) -> bool:
    return effective_plan(user) == "pro"
