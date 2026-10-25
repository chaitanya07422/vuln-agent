from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding
from vuln_agent.tools.safety import url_is_safe_target

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


def parse_paths_from_llm(text: str, limit: int = 8) -> List[str]:
    paths: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip().strip("-*`'\" ")
        if not line.startswith("/"):
            m = re.search(r"(/[\w./?=&%~+-]+)", line)
            if not m:
                continue
            line = m.group(1)
        # single path only, no scheme/host
        if "://" in line or line.startswith("//"):
            continue
        path = line.split()[0]
        if not path.startswith("/"):
            continue
        if path not in paths:
            paths.append(path)
        if len(paths) >= limit:
            break
    return paths


class AdaptAgent(BaseAgent):
    name = "adapt"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def _candidate_paths(self, ctx: ScanContext, limit: int) -> List[str]:
        paths = list(CANDIDATE_PATHS)
        if ctx.llm and ctx.llm.provider_name("adapt") != "null":
            prompt = (
                f"Target URL: {ctx.url}\n"
                f"Fingerprint: {ctx.fingerprint}\n"
                "Suggest up to 8 one-shot GET paths to check for common misconfigurations "
                "(leaks, debug, admin, graphql, actuator). Reply with one path per line only, "
                "starting with /. No explanations."
            )
            try:
                text = await ctx.llm.complete(
                    "adapt",
                    prompt,
                    system="You propose safe detect-only web paths. Never suggest password sprays.",
                )
                llm_paths = parse_paths_from_llm(text, limit=limit)
                # Prefer LLM paths first, then fill from heuristics
                merged: List[str] = []
                for p in llm_paths + paths:
                    if p not in merged:
                        merged.append(p)
                paths = merged
            except Exception:
                pass
        return paths[:limit]

    async def run(self, ctx: ScanContext) -> None:
        tags = set((ctx.fingerprint or {}).get("tags") or [])
        if "unknown" not in tags and "wordpress" in tags:
            return

        limit = 8
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        paths = await self._candidate_paths(ctx, limit)
        tried = 0
        for path in paths:
            if tried >= limit:
                break
            target = urljoin(base, path.lstrip("/"))
            if not url_is_safe_target(target, ctx.scope.allow_hosts):
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
            sev = "high" if any(x in path for x in (".env", ".git", "actuator/env")) else "medium"
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
