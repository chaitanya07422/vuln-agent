from __future__ import annotations

import re
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: manifests, robots, sitemap, generator meta. No dependency exploit.


class DependencyMetaAgent(BaseAgent):
    name = "dependency_meta"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=150_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        generators = []
        if home.get("ok"):
            html = home.get("body") or ""
            for m in re.finditer(
                r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
                html,
                re.I,
            ):
                generators.append(m.group(1)[:120])
            for m in re.finditer(
                r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""",
                html,
                re.I,
            ):
                generators.append(m.group(1)[:120])

        manifests = []
        for path in (
            "/package.json",
            "/composer.json",
            "/Gemfile",
            "/requirements.txt",
            "/yarn.lock",
            "/package-lock.json",
            "/manifest.json",
            "/asset-manifest.json",
            "/.nvmrc",
        ):
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=30_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
                continue
            body = resp.get("body") or ""
            headers = resp.get("headers") or {}
            ctype = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
            # SPA shells often return HTML 200 for any path
            if "text/html" in ctype and path.endswith((".json", ".txt", "Gemfile", ".nvmrc")):
                if "<html" in body.lower()[:200]:
                    continue
            if path.endswith(".json") and not body.strip().startswith(("{", "[")):
                continue
            manifests.append(path)
            sev = "medium" if path in ("/package.json", "/composer.json", "/Gemfile", "/requirements.txt", "/yarn.lock", "/package-lock.json") else "low"
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=f"Dependency/manifest file publicly readable: {path}",
                    evidence_url=target,
                    evidence_snippet=body[:160],
                    fix="Do not serve package manifests or lockfiles from the production web root.",
                    tags=["dependencies", "meta"],
                )
            )

        for g in generators[:3]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Generator meta tag: {g}",
                    evidence_url=ctx.url,
                    evidence_snippet=g,
                    tags=["meta", "fingerprint"],
                )
            )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["dependency_meta"] = {
            "generators": generators[:5],
            "manifests": manifests,
        }
