from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: inspect Set-Cookie flags. No session fixation or theft.


class CookieFlagsAgent(BaseAgent):
    name = "cookie_flags"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        headers = resp.get("headers") or {}
        # httpx may collapse set-cookie; also check raw-style keys
        cookies = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                cookies.append(v)
        # Multiple Set-Cookie sometimes joined
        if not cookies:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["cookie_flags"] = {"count": 0}
            return

        issues = []
        for raw in cookies:
            for part in _split_cookies(raw):
                lower = part.lower()
                name = part.split("=", 1)[0].strip()
                if not name or name.lower() in ("path", "domain", "expires", "max-age"):
                    continue
                missing = []
                if "secure" not in lower and ctx.url.lower().startswith("https://"):
                    missing.append("Secure")
                if "httponly" not in lower:
                    missing.append("HttpOnly")
                if "samesite" not in lower:
                    missing.append("SameSite")
                if missing:
                    issues.append({"name": name, "missing": missing})
                    sev = "medium" if "Secure" in missing or "HttpOnly" in missing else "low"
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity=sev,  # type: ignore[arg-type]
                            title=f"Cookie '{name}' missing {', '.join(missing)}",
                            evidence_url=ctx.url,
                            evidence_snippet=part[:160],
                            fix="Set Secure, HttpOnly, and SameSite on session cookies.",
                            tags=["cookies", "session"],
                        )
                    )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cookie_flags"] = {"count": len(cookies), "issues": issues[:10]}


def _split_cookies(raw: str) -> list:
    # Naive split on comma only when next token looks like a new cookie (name=)
    import re

    parts = re.split(r",(?=\s*[^;=]+=)", raw)
    return [p.strip() for p in parts if p.strip()]
