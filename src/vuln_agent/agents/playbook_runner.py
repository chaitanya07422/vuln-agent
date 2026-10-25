from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding


def _body_match(body: str, needles: Optional[List[str]]) -> bool:
    if not needles:
        return True
    lower = (body or "").lower()
    return any(n.lower() in lower for n in needles)


def _header_match(headers: Dict[str, str], rules: Optional[Dict[str, str]]) -> bool:
    if not rules:
        return True
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    for key, expected in rules.items():
        actual = lower.get(key.lower(), "")
        if expected.lower() not in actual.lower():
            return False
    return True


def _header_exists(headers: Dict[str, str], names: Optional[List[str]]) -> bool:
    if not names:
        return True
    lower = {k.lower() for k in (headers or {}).keys()}
    return any(n.lower() in lower for n in names)


def in_scope(url: str, allow_hosts: List[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    for allowed in allow_hosts:
        a = allowed.lower()
        if host == a or host.endswith("." + a):
            return True
    return False


async def run_http_steps(
    ctx: ScanContext,
    *,
    agent_name: str,
    steps: List[Dict[str, Any]],
) -> None:
    base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
    for step in steps:
        path = step.get("path")
        if not path:
            continue
        target = urljoin(base, path.lstrip("/")) if path.startswith("/") else urljoin(base, path)
        if not in_scope(target, ctx.scope.allow_hosts):
            continue

        method = (step.get("method") or "GET").upper()
        headers = dict(step.get("headers") or {})
        if step.get("origin"):
            headers["Origin"] = step["origin"]

        resp = await ctx.tools.http_request(
            method=method,
            url=target,
            headers=headers or None,
            body=step.get("body"),
        )
        await ctx.audit_event(agent=agent_name, tool="http_request", url=target, ok=resp.get("ok"))

        if not resp.get("ok"):
            continue

        status = resp.get("status_code")
        wanted_status = step.get("finding_if_status")
        if wanted_status is not None and status not in wanted_status:
            continue

        body = resp.get("body") or ""
        headers_out = resp.get("headers") or {}

        if not _body_match(body, step.get("finding_if_body_contains")):
            continue
        if not _header_match(headers_out, step.get("finding_if_header_contains")):
            continue
        if step.get("finding_if_header_exists") and not _header_exists(
            headers_out, step.get("finding_if_header_exists")
        ):
            continue

        snippet = body[:400].replace("\n", " ")
        await ctx.emit_finding(
            Finding(
                agent=agent_name,
                severity=step.get("severity") or "medium",
                title=step.get("title") or f"{agent_name} hit {path}",
                evidence_url=resp.get("url") or target,
                evidence_snippet=f"HTTP {status}; {snippet}",
                fix=step.get("fix"),
                tags=[agent_name, *(step.get("tags") or [])],
            )
        )
