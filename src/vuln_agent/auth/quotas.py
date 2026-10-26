from __future__ import annotations

from typing import Any, Dict, Optional

from vuln_agent.auth.deps import effective_plan

# Lifetime guest scans (no account) — never refills
GUEST_LIFETIME_LIMIT = 2
# Signed-in Free plan — total scans (lifetime for that account)
FREE_SCAN_LIMIT = 5
# Pro — generous create + history caps
PRO_SCAN_LIMIT = 500

HISTORY_LIMITS = {"free": FREE_SCAN_LIMIT, "pro": PRO_SCAN_LIMIT, "anon": 0}
CREATE_LIMITS = {"free": FREE_SCAN_LIMIT, "pro": PRO_SCAN_LIMIT, "anon": GUEST_LIFETIME_LIMIT}


def history_limit(user: Optional[Dict[str, Any]]) -> int:
    return HISTORY_LIMITS.get(effective_plan(user), FREE_SCAN_LIMIT)


def create_limit(user: Optional[Dict[str, Any]]) -> int:
    return CREATE_LIMITS.get(effective_plan(user), FREE_SCAN_LIMIT)


def is_pro(user: Optional[Dict[str, Any]]) -> bool:
    return effective_plan(user) == "pro"


def quota_payload(
    *,
    mode: str,
    limit: int,
    used: int,
    deep_credits: int = 0,
) -> Dict[str, Any]:
    remaining = max(0, limit - used)
    return {
        "mode": mode,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "can_scan": remaining > 0 or mode == "pro",
        "deep_credits": deep_credits,
        "guest_lifetime": GUEST_LIFETIME_LIMIT,
        "free_limit": FREE_SCAN_LIMIT,
    }
