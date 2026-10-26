from __future__ import annotations

import json
from typing import List, Set
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import looks_like_html_document
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: unauth access to private-looking API paths / sequential IDs.
# True IDOR (two accounts) is out of scope.

CANDIDATES = (
    "/api/users",
    "/api/users/1",
    "/api/user/1",
    "/api/me",
    "/api/account",
    "/api/accounts/1",
    "/api/orders",
    "/api/orders/1",
    "/api/admin",
    "/api/admin/users",
    "/api/internal",
    "/api/v1/users",
    "/api/v1/users/1",
    "/users/1.json",
    "/admin/users",
    "/wp-json/wp/v2/users",
)

SENSITIVE_KEYS = (
    "email",
    "password",
    "token",
    "secret",
    "ssn",
    "phone",
    "address",
    "role",
    "admin",
    "balance",
    "card",
)


class AccessHintAgent(BaseAgent):
    name = "access_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        paths: List[str] = list(CANDIDATES)
        for p in (ctx.fingerprint or {}).get("js_api_paths") or []:
            if isinstance(p, str) and p.startswith("/api/"):
                paths.append(p.split("?")[0])
                # sequential id guess
                if not p.rstrip("/").endswith(("1", "me")):
                    paths.append(p.rstrip("/") + "/1")

        seen: Set[str] = set()
        hits = []
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            if len(seen) > 20:
                break
            target = urljoin(base, path.lstrip("/"))
            if not in_scope(target, ctx.scope.allow_hosts):
                continue
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=20_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            body = resp.get("body") or ""
            headers = resp.get("headers") or {}
            if code != 200:
                continue
            if looks_like_html_document(body, headers):
                # Login wall HTML is not a data leak
                if any(x in body.lower() for x in ("password", "sign in", "log in")):
                    continue
                # Admin HTML without auth wall
                if "admin" in path.lower() and len(body) > 200:
                    hits.append(path)
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"Unauthenticated admin-like page reachable: {path}",
                            evidence_url=target,
                            evidence_snippet=body[:160],
                            fix="Require authentication and authorization for admin/user resources.",
                            tags=["access", "idor"],
                        )
                    )
                continue

            # JSON-looking success
            sensitive = False
            try:
                data = json.loads(body)
                blob = json.dumps(data).lower()
                sensitive = any(k in blob for k in SENSITIVE_KEYS) or (
                    isinstance(data, list) and len(data) > 0
                ) or (isinstance(data, dict) and len(data) > 0)
            except json.JSONDecodeError:
                if body.strip().startswith(("{", "[")):
                    sensitive = True
                else:
                    continue

            if sensitive and any(
                x in path.lower() for x in ("user", "order", "account", "admin", "me", "internal")
            ):
                hits.append(path)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high" if "/1" in path or path.endswith("/me") else "medium",
                        title=f"Unauthenticated data-like response at {path}",
                        evidence_url=target,
                        evidence_snippet=body[:180],
                        fix="Enforce authn/authz on APIs; never expose object graphs by predictable IDs without checks.",
                        tags=["access", "idor", "api"],
                    )
                )

            # Dangerous verbs without auth
            for method in ("PUT", "DELETE"):
                if "users" not in path and "orders" not in path and "admin" not in path:
                    continue
                mresp = await ctx.tools.http_request(
                    method=method,
                    url=target,
                    headers={"Content-Type": "application/json"},
                    body="{}",
                    max_body_bytes=4000,
                )
                if not mresp.get("ok"):
                    continue
                mcode = mresp.get("status_code") or 0
                if mcode in (200, 204) and not looks_like_html_document(mresp.get("body") or "", mresp.get("headers") or {}):
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title=f"Unauthenticated {method} accepted at {path}",
                            evidence_url=target,
                            evidence_snippet=f"HTTP {mcode}",
                            fix="Reject unauthenticated mutating methods; require auth and object-level authorization.",
                            tags=["access", "api"],
                        )
                    )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["access_hint"] = {"hits": hits[:15]}
