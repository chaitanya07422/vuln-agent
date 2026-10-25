from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import (
    looks_like_dotenv,
    looks_like_git_head,
    looks_like_html_document,
)
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


def _interesting(path: str, status: int, body: str, headers: dict) -> bool:
    if status != 200:
        return False
    # SPA soft-404: never treat HTML shell as a hit
    if looks_like_html_document(body, headers):
        return False

    path_l = path.lower()
    if path_l.endswith("head") or ".git/head" in path_l:
        return looks_like_git_head(body)
    if path_l.endswith(".env") or "/.env" in path_l:
        return looks_like_dotenv(body)
    if "graphql" in path_l:
        lower = body.lower()
        return any(x in lower for x in ("__schema", "graphql", '"data"', "must provide query"))
    if "actuator" in path_l:
        return "{" in body[:300] and not looks_like_html_document(body, headers)
    if "server-status" in path_l:
        return "scoreboard" in body.lower() or "apache server status" in body.lower()
    # generic unknown path: require non-HTML with some substance
    return len(body) > 40


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
            status = resp.get("status_code") or 0
            body = resp.get("body") or ""
            headers = resp.get("headers") or {}
            if not _interesting(path, int(status), body, headers):
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
