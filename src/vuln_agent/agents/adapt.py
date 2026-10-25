from __future__ import annotations

import ipaddress
from typing import List
from urllib.parse import urljoin, urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Heuristic one-shot paths when stack is unknown (no LLM required for v1)
CANDIDATE_PATHS: List[str] = [
    "/.env",
    "/.git/HEAD",
    "/actuator/health",
    "/actuator/env",
    "/server-status",
    "/graphql",
    "/graphiql",
    "/api/graphql",
]


def _is_public_host(host: str) -> bool:
    try:
        # reject literal IPs that are private
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        # hostname — block obvious local names
        h = host.lower()
        if h in {"localhost", "127.0.0.1", "0.0.0.0"} or h.endswith(".local"):
            return False
        return True


class AdaptAgent(BaseAgent):
    name = "adapt"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = set((ctx.fingerprint or {}).get("tags") or [])
        # Run when unknown OR always with a small budget of extra paths
        if "unknown" not in tags and "wordpress" in tags:
            return

        limit = 8
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        tried = 0
        for path in CANDIDATE_PATHS:
            if tried >= limit:
                break
            target = urljoin(base, path.lstrip("/"))
            host = urlparse(target).hostname or ""
            if not _is_public_host(host) or not in_scope(target, ctx.scope.allow_hosts):
                continue
            tried += 1
            resp = await ctx.tools.http_request(method="GET", url=target)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            status = resp.get("status_code")
            body = (resp.get("body") or "")[:300]
            interesting = status == 200 and len(body) > 20
            if path.endswith("HEAD") and "ref:" in body:
                interesting = True
            if path.endswith(".env") and "=" in body and status == 200:
                interesting = True
            if "graphql" in path.lower() and status == 200 and (
                "graphql" in body.lower() or "__schema" in body.lower() or "query" in body.lower()
            ):
                interesting = True
            if "actuator" in path and status == 200:
                interesting = True
            if not interesting:
                continue
            sev = "high" if path in ("/.env", "/.git/HEAD", "/actuator/env") else "medium"
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,
                    title=f"Adapt probe hit: {path}",
                    evidence_url=resp.get("url") or target,
                    evidence_snippet=f"HTTP {status}; {body[:200]}",
                    fix="Remove public access to debug/admin/leak paths.",
                    tags=["adapt", "probe"],
                )
            )
