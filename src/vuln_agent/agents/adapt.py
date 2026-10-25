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
    "/api/jobs",
    "/api/categories",
    "/api/uploads/request-url",
    "/api/admin/login",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
]

ADAPT_SYSTEM = (
    "You help pick ONE-SHOT detect-only HTTP paths for an external website scan. "
    "Prefer API and upload/admin surfaces over random CMS paths when the stack is SPA/Express/React. "
    "When JS already lists /api/* paths, suggest close cousins only (siblings under same prefix). "
    "Never suggest password sprays or multi-step exploits. "
    "Reply with up to 8 paths only, one per line, each starting with /. No commentary."
)


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
    if status not in (200, 401, 403):
        return False
    path_l = path.lower()

    # Auth-gated APIs are interesting even with small JSON bodies
    if status in (401, 403) and (
        "upload" in path_l or "admin" in path_l or "presign" in path_l or path_l.startswith("/api/")
    ):
        if looks_like_html_document(body, headers):
            return False
        return True

    if status != 200:
        return False
    if looks_like_html_document(body, headers):
        return False

    if path_l.endswith("head") or ".git/head" in path_l:
        return looks_like_git_head(body)
    if path_l.endswith(".env") or "/.env" in path_l:
        return looks_like_dotenv(body)
    if "graphql" in path_l:
        lower = body.lower()
        return any(x in lower for x in ("__schema", "graphql", '"data"', "must provide query"))
    if "actuator" in path_l:
        return "{" in body[:300]
    if "server-status" in path_l:
        return "scoreboard" in body.lower() or "apache server status" in body.lower()
    if path_l.startswith("/api/"):
        # public JSON API
        return body.strip()[:1] in "{[" or "json" in (headers.get("content-type") or "").lower()
    return len(body) > 40


class AdaptAgent(BaseAgent):
    name = "adapt"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def _candidate_paths(self, ctx: ScanContext, limit: int) -> List[str]:
        paths: List[str] = list(CANDIDATE_PATHS)
        # Prefer paths already discovered from JS
        js_paths = list((ctx.fingerprint or {}).get("js_api_paths") or [])
        for p in js_paths:
            if p not in paths:
                paths.insert(0, p)

        tags = list((ctx.fingerprint or {}).get("tags") or [])
        if ctx.llm and ctx.llm.provider_name("adapt") != "null":
            prompt = (
                f"Target URL: {ctx.url}\n"
                f"Fingerprint tags: {tags}\n"
                f"Fingerprint detail: { {k:v for k,v in (ctx.fingerprint or {}).items() if k!='js_api_paths'} }\n"
                f"API paths already seen in JS: {js_paths[:30]}\n"
                "Suggest additional one-shot paths useful for finding: "
                "public JSON APIs, upload/presign, admin login, object/file routes, "
                "swagger/docs, env/git leaks. "
                "If SPA/Express, prioritize /api/* over WordPress paths."
            )
            try:
                text = await ctx.llm.complete("adapt", prompt, system=ADAPT_SYSTEM)
                llm_paths = parse_paths_from_llm(text, limit=limit)
                merged: List[str] = []
                for p in llm_paths + paths:
                    if p not in merged:
                        merged.append(p)
                paths = merged
            except Exception:
                pass
        return paths[: max(limit, 12)]

    async def run(self, ctx: ScanContext) -> None:
        tags = set((ctx.fingerprint or {}).get("tags") or [])
        if "unknown" not in tags and "wordpress" in tags:
            # still allow if js paths exist
            if not (ctx.fingerprint or {}).get("js_api_paths"):
                return

        limit = 12
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        paths = await self._candidate_paths(ctx, limit)
        tried = 0
        for path in paths:
            if tried >= limit:
                break
            # POST for login/presign style endpoints once
            method = "GET"
            body = None
            headers = {"Accept": "application/json"}
            pl = path.lower()
            if "request-url" in pl or "presign" in pl:
                method = "POST"
                headers["Content-Type"] = "application/json"
                body = '{"name":"t.pdf","size":1,"contentType":"application/pdf"}'
            elif pl.endswith("/login") and "/api/" in pl:
                method = "POST"
                headers["Content-Type"] = "application/json"
                body = '{"email":"scan@example.com","password":"invalid-scan-probe"}'

            target = urljoin(base, path.lstrip("/"))
            if not url_is_safe_target(target, ctx.scope.allow_hosts):
                continue
            tried += 1
            resp = await ctx.tools.http_request(method=method, url=target, headers=headers, body=body)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            status = int(resp.get("status_code") or 0)
            resp_body = resp.get("body") or ""
            resp_headers = resp.get("headers") or {}
            if not _interesting(path, status, resp_body, resp_headers):
                continue
            if status in (401, 403):
                sev = "medium"
                title = f"Protected API responds: {method} {path}"
            elif path.startswith("/api/") and status == 200:
                sev = "info"
                title = f"Public API responds: {method} {path}"
            else:
                sev = "high" if any(x in path for x in (".env", ".git", "actuator/env")) else "medium"
                title = f"Adapt probe hit: {path}"
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    evidence_url=resp.get("url") or target,
                    evidence_snippet=f"HTTP {status}; {resp_body[:200]}",
                    fix="Review exposure; require auth where appropriate; lock down debug/upload routes.",
                    tags=["adapt", "probe"],
                )
            )
