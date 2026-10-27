from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: inspect Set-Cookie flags. No session fixation or theft.

# Bot/CDN / analytics — flag gaps are noise for "session theft" narratives.
# These cookies are often intentionally readable by JS (no HttpOnly) or set by edges.
SKIP_OR_INFO_PREFIXES = (
    "ak_bmsc",
    "bm_",
    "_abck",
    "abck",
    "_ga",
    "_gid",
    "_fbp",
    "_gcl",
    "__cf",
    "cf_",
    "_clck",
    "_clsk",
    "AMP_",
    "_hj",
    "_uet",
    "_tt_",
    "Optanon",
    "CookieConsent",
)

# Exact bot/edge names that do not start with the prefixes above
SKIP_OR_INFO_EXACT = frozenset(
    {
        "ak_bmsc",
        "_abck",
        "abck",
        "bm_sz",
        "bm_sv",
        "bm_mi",
        "bm_lso",
        "RT",  # Akamai mPulse
    }
)


def is_bot_or_analytics_cookie(name: str) -> bool:
    lname = (name or "").strip().lower()
    if not lname:
        return False
    if lname in {n.lower() for n in SKIP_OR_INFO_EXACT}:
        return True
    return any(lname.startswith(p.lower()) or lname == p.rstrip("_").lower() for p in SKIP_OR_INFO_PREFIXES)

MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


def _looks_like_cookie_name(token: str) -> bool:
    t = token.strip()
    if not t or "=" not in t:
        return False
    name = t.split("=", 1)[0].strip()
    # Real cookie names: token-ish, not date fragments ("26 Oct 2025 12:00:00 GMT")
    if not re.fullmatch(r"[A-Za-z0-9_!#$%&'*+.^`|~-]{1,64}", name):
        return False
    if re.search(r"\d{4}", name) and any(m in name.lower() for m in MONTHS):
        return False
    if re.match(r"^\d", name) and " " in name:
        return False
    return True


def split_set_cookie_header(raw: str) -> List[str]:
    """Split joined Set-Cookie values without breaking Expires=Sun, 26 Oct … dates."""
    if not raw:
        return []
    parts: List[str] = []
    buf: List[str] = []
    i = 0
    s = raw
    while i < len(s):
        if s[i] == ",":
            rest = s[i + 1 :].lstrip()
            # Next cookie only if remainder starts with name=
            if _looks_like_cookie_name(rest.split(";", 1)[0]):
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
        buf.append(s[i])
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p and _looks_like_cookie_name(p.split(";", 1)[0])]


def _parse_expires(attrs_lower: str) -> Optional[datetime]:
    m = re.search(
        r"expires=(\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+gmt)",
        attrs_lower,
        re.I,
    )
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(m.group(1), "%a, %d %b %Y %H:%M:%S gmt").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _max_age(attrs_lower: str) -> Optional[int]:
    m = re.search(r"max-age\s*=\s*(-?\d+)", attrs_lower)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def is_deletion_cookie(name_value: str, attrs: str) -> bool:
    """Empty value and/or Max-Age<=0 / past Expires → clearing cookie, not a live session."""
    if "=" not in name_value:
        return True
    _, _, value = name_value.partition("=")
    value = value.strip().strip('"')
    attrs_l = attrs.lower()
    ma = _max_age(attrs_l)
    if ma is not None and ma <= 0:
        return True
    exp = _parse_expires(attrs_l)
    if exp is not None and exp <= datetime.now(timezone.utc):
        return True
    if value == "":
        return True
    return False


def parse_cookie(raw: str) -> Optional[Tuple[str, str, str, bool]]:
    """Return (name, value, attrs, is_delete) or None if not a real cookie."""
    raw = (raw or "").strip()
    if not raw or not _looks_like_cookie_name(raw.split(";", 1)[0]):
        return None
    first, _, rest = raw.partition(";")
    name, _, value = first.partition("=")
    name = name.strip()
    value = value.strip()
    if not name or name.lower() in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
        return None
    return name, value, rest, is_deletion_cookie(first, rest)


class CookieFlagsAgent(BaseAgent):
    name = "cookie_flags"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        cookies: List[str] = list(resp.get("set_cookie") or [])
        if not cookies:
            headers = resp.get("headers") or {}
            for k, v in headers.items():
                if k.lower() == "set-cookie" and v:
                    cookies.extend(split_set_cookie_header(v))

        if not cookies:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["cookie_flags"] = {"count": 0}
            return

        issues = []
        for raw in cookies:
            parsed = parse_cookie(raw)
            if not parsed:
                continue
            name, value, attrs, is_delete = parsed
            lower = f"{name}={value};{attrs}".lower()
            lname = name.lower()

            if is_bot_or_analytics_cookie(name):
                # Bot/CDN cookies — skip missing-flag noise
                continue

            missing = []
            if "secure" not in lower and ctx.url.lower().startswith("https://"):
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if not missing:
                continue

            if is_delete:
                # Real hygiene on clear paths, but not session theft
                issues.append({"name": name, "missing": missing, "delete": True})
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title=f"Clearing cookie '{name}' missing {', '.join(missing)}",
                        evidence_url=ctx.url,
                        evidence_snippet=raw[:160],
                        fix="Include Secure, HttpOnly, and SameSite even when clearing cookies.",
                        tags=["cookies", "hygiene"],
                    )
                )
                continue

            issues.append({"name": name, "missing": missing, "delete": False})
            sev = "medium" if ("Secure" in missing or "HttpOnly" in missing) else "low"
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=f"Cookie '{name}' missing {', '.join(missing)}",
                    evidence_url=ctx.url,
                    evidence_snippet=raw[:160],
                    fix="Set Secure, HttpOnly, and SameSite on session cookies.",
                    tags=["cookies", "session"],
                )
            )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cookie_flags"] = {"count": len(cookies), "issues": issues[:10]}
