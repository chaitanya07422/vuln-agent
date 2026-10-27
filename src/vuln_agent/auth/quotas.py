from __future__ import annotations

from typing import Any, Dict, Optional

from vuln_agent.auth.deps import effective_plan

# Lifetime guest scans (no account) — never refills
GUEST_LIFETIME_LIMIT = 2
# First guest scan is full detail; second is teaser (1 finding)
GUEST_FULL_LIMIT = 1
# Signed-in Free: first N owned scans get full detail
FREE_FULL_LIMIT = 2
# Free can keep creating beyond full allotment (teaser results)
FREE_SCAN_LIMIT = 10
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
    full_limit: Optional[int] = None,
    full_used: Optional[int] = None,
) -> Dict[str, Any]:
    remaining = max(0, limit - used)
    if full_limit is None:
        full_limit = GUEST_FULL_LIMIT if mode == "guest" else FREE_FULL_LIMIT if mode == "free" else limit
    if full_used is None:
        full_used = min(used, full_limit) if mode != "pro" else used
    full_remaining = max(0, full_limit - full_used) if mode != "pro" else remaining
    return {
        "mode": mode,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "can_scan": remaining > 0 or mode == "pro",
        "deep_credits": deep_credits,
        "guest_lifetime": GUEST_LIFETIME_LIMIT,
        "free_limit": FREE_FULL_LIMIT,
        "full_limit": full_limit if mode != "pro" else limit,
        "full_used": full_used if mode != "pro" else used,
        "full_remaining": full_remaining if mode != "pro" else remaining,
        "next_detail": "full" if (mode == "pro" or full_remaining > 0) else "teaser",
    }
