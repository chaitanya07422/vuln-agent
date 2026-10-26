from __future__ import annotations

from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Fingerprint-gated for Next/React. Detect-only: /.next, source maps, public env.


class NextReactAgent(BaseAgent):
    name = "next_react"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=100_000)
        html = (home.get("body") or "") if home.get("ok") else ""
        looks_next = "nextjs" in tags or "/_next/" in html or "__NEXT_DATA__" in html
        looks_react = "react" in html.lower() or "data-reactroot" in html.lower() or looks_next
        if not looks_next and not looks_react:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["next_react"] = {"skipped": True}
            return

        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        hits = []
        paths = [
            "/_next/static/",
            "/.next/BUILD_ID",
            "/_next/static/chunks/main.js.map",
            "/static/js/main.js.map",
            "/asset-manifest.json",
        ]
        for path in paths:
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=40_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            body = resp.get("body") or ""
            if path.endswith(".map") and code == 200 and ("mappings" in body or "sources" in body):
                hits.append(path)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="JavaScript source map publicly accessible",
                        evidence_url=target,
                        evidence_snippet=body[:120],
                        fix="Do not deploy .map files to production CDNs; keep them private for error tooling.",
                        tags=["nextjs", "sourcemap"],
                    )
                )
            if path.endswith("BUILD_ID") and code == 200 and len(body.strip()) < 80:
                hits.append(path)

        # Public NEXT_PUBLIC / REACT_APP in inline HTML
        for needle, title, sev in (
            ("NEXT_PUBLIC_", "Next.js NEXT_PUBLIC_ env values embedded in page", "low"),
            ("REACT_APP_", "React REACT_APP_ env values embedded in page", "low"),
            ("aws_secret", "Possible secret-like string in frontend", "high"),
        ):
            if needle.lower() in html.lower() and needle != "aws_secret":
                hits.append(needle)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        title=title,
                        evidence_url=ctx.url,
                        evidence_snippet=needle,
                        fix="Ensure only non-sensitive public config is embedded; never put secrets in NEXT_PUBLIC_/REACT_APP_.",
                        tags=["nextjs", "env"],
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["next_react"] = {"hits": hits}
