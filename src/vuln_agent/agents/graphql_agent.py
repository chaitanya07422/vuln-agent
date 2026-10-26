from __future__ import annotations

import json
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: find /graphql; safe introspection / error-shape probe only. No mutation abuse.

PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
INTROSPECTION = '{"query":"{ __schema { queryType { name } } }"}'


class GraphqlAgent(BaseAgent):
    name = "graphql"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        found = []
        for path in PATHS:
            target = urljoin(base, path.lstrip("/"))
            # GET probe
            get = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=8000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=get.get("ok"))
            body = (get.get("body") or "").lower() if get.get("ok") else ""
            code = get.get("status_code") or 0 if get.get("ok") else 0
            looks = (
                "graphql" in body
                or "__schema" in body
                or "graphiql" in body
                or '"errors"' in body
                or (
                    code in (200, 400, 405)
                    and ("query" in body or "graphql" in path)
                )
            )

            post = await ctx.tools.http_request(
                method="POST",
                url=target,
                headers={"Content-Type": "application/json"},
                body=INTROSPECTION,
                max_body_bytes=20_000,
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, method="POST", ok=post.get("ok"))
            post_body = post.get("body") or "" if post.get("ok") else ""
            post_code = post.get("status_code") or 0 if post.get("ok") else 0

            introspection_open = False
            if post.get("ok") and post_code == 200:
                try:
                    data = json.loads(post_body)
                    if isinstance(data, dict) and data.get("data", {}).get("__schema"):
                        introspection_open = True
                except json.JSONDecodeError:
                    if "__schema" in post_body and "queryType" in post_body:
                        introspection_open = True

            if introspection_open or (looks and post.get("ok") and post_code in (200, 400)):
                found.append(path)
                if introspection_open:
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title=f"GraphQL introspection enabled at {path}",
                            evidence_url=target,
                            evidence_snippet=post_body[:200],
                            fix="Disable introspection in production; require auth on GraphQL.",
                            tags=["graphql", "introspection"],
                        )
                    )
                elif "errors" in post_body.lower() and "syntax" in post_body.lower():
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="low",
                            title=f"GraphQL endpoint responds at {path}",
                            evidence_url=target,
                            evidence_snippet=post_body[:160],
                            fix="Ensure GraphQL is authenticated and does not leak schema via errors.",
                            tags=["graphql"],
                        )
                    )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["graphql"] = {"paths": found}
