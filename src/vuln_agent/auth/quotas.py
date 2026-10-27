from __future__ import annotations

import os
from typing import Any, Dict, Optional

from vuln_agent.auth.deps import effective_plan


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(0, int(str(raw).strip()))
    except ValueError:
        return default


# Lifetime guest scans (no account) — never refills
GUEST_LIFETIME_LIMIT = _int_env("VULN_AGENT_GUEST_LIFETIME_LIMIT", 2)
# First guest scan is full detail; second is teaser (1 finding)
GUEST_FULL_LIMIT = _int_env("VULN_AGENT_GUEST_FULL_LIMIT", 1)
# Signed-in Free: first N *web* scans get full detail
FREE_FULL_LIMIT = _int_env("VULN_AGENT_FREE_FULL_LIMIT", 2)
# Free web create cap: full briefs + 1 locked preview, then upgrade
# (MCP is a separate bucket)
FREE_SCAN_LIMIT = _int_env("VULN_AGENT_FREE_SCAN_LIMIT", 3)
# Free MCP / CLI create cap (API key auth) — independent of web
FREE_MCP_SCAN_LIMIT = _int_env("VULN_AGENT_FREE_MCP_SCAN_LIMIT", 1)
# Pro create + history caps (override on Oracle via env)
PRO_SCAN_LIMIT = _int_env("VULN_AGENT_PRO_SCAN_LIMIT", 30)

SCAN_SOURCE_WEB = "web"
SCAN_SOURCE_MCP = "mcp"

HISTORY_LIMITS = {
    "free": FREE_SCAN_LIMIT + FREE_MCP_SCAN_LIMIT,
    "pro": PRO_SCAN_LIMIT,
    "anon": 0,
}
CREATE_LIMITS = {"free": FREE_SCAN_LIMIT, "pro": PRO_SCAN_LIMIT, "anon": GUEST_LIFETIME_LIMIT}


def history_limit(user: Optional[Dict[str, Any]]) -> int:
    return HISTORY_LIMITS.get(effective_plan(user), FREE_SCAN_LIMIT + FREE_MCP_SCAN_LIMIT)


def create_limit(user: Optional[Dict[str, Any]], *, source: str = SCAN_SOURCE_WEB) -> int:
    plan = effective_plan(user)
    # Pro: one shared pool for web + MCP (source ignored).
    if plan == "pro":
        return PRO_SCAN_LIMIT
    if source == SCAN_SOURCE_MCP:
        if plan == "free":
            return FREE_MCP_SCAN_LIMIT
        return 0
    return CREATE_LIMITS.get(plan, FREE_SCAN_LIMIT)


def normalize_scan_source(source: Optional[str]) -> str:
    if source == SCAN_SOURCE_MCP:
        return SCAN_SOURCE_MCP
    return SCAN_SOURCE_WEB


def is_pro(user: Optional[Dict[str, Any]]) -> bool:
    return effective_plan(user) == "pro"


def pro_shares_quota(user: Optional[Dict[str, Any]]) -> bool:
    """Pro web + MCP scans share one PRO_SCAN_LIMIT counter."""
    return is_pro(user)


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
        # Pro is capped by VULN_AGENT_PRO_SCAN_LIMIT like Free — no unlimited bypass
        "can_scan": remaining > 0,
        "deep_credits": deep_credits,
        "guest_lifetime": GUEST_LIFETIME_LIMIT,
        "free_limit": FREE_FULL_LIMIT,
        "full_limit": full_limit if mode != "pro" else limit,
        "full_used": full_used if mode != "pro" else used,
        "full_remaining": full_remaining if mode != "pro" else remaining,
        "next_detail": "full" if (mode == "pro" or full_remaining > 0) else "teaser",
    }
