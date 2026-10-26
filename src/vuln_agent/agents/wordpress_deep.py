from __future__ import annotations

from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Fingerprint-gated. Detect-only: plugin/theme paths, xmlrpc pingback, deeper user enum. No brute.


class WordpressDeepAgent(BaseAgent):
    name = "wordpress_deep"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        if "wordpress" not in tags:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["wordpress_deep"] = {"skipped": True, "reason": "not wordpress"}
            return

        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        hits = []

        paths = [
            "/wp-json/wp/v2/users",
            "/?author=1",
            "/wp-content/debug.log",
            "/wp-content/uploads/",
            "/xmlrpc.php",
            "/wp-includes/wlwmanifest.xml",
            "/wp-content/plugins/revslider/",
            "/wp-content/plugins/elementor/",
            "/wp-content/plugins/woocommerce/",
            "/wp-content/themes/twentytwentyfour/style.css",
        ]
        for path in paths:
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=30_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            body = resp.get("body") or ""
            if path.endswith("users") and code == 200 and ("slug" in body or "name" in body):
                hits.append(path)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="WordPress REST user enumeration open",
                        evidence_url=target,
                        evidence_snippet=body[:160],
                        fix="Disable public user listing in REST; restrict with auth plugins/WAF.",
                        tags=["wordpress", "users"],
                    )
                )
            if path == "/wp-content/debug.log" and code == 200 and len(body) > 40:
                hits.append(path)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high",
                        title="WordPress debug.log publicly readable",
                        evidence_url=target,
                        evidence_snippet=body[:160],
                        fix="Delete/deny public access to debug.log; disable WP_DEBUG_LOG on production.",
                        tags=["wordpress", "leak"],
                    )
                )
            if path == "/xmlrpc.php" and code in (200, 405):
                # pingback multicall presence — system.listMethods only
                ping = await ctx.tools.http_request(
                    method="POST",
                    url=target,
                    headers={"Content-Type": "text/xml"},
                    body=(
                        '<?xml version="1.0"?>'
                        "<methodCall><methodName>system.listMethods</methodName>"
                        "<params></params></methodCall>"
                    ),
                    max_body_bytes=20_000,
                )
                if ping.get("ok") and "pingback.ping" in (ping.get("body") or ""):
                    hits.append("xmlrpc-pingback")
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title="WordPress XML-RPC pingback enabled",
                            evidence_url=target,
                            evidence_snippet="pingback.ping in system.listMethods",
                            fix="Disable xmlrpc or block pingback; prefer REST with auth.",
                            tags=["wordpress", "xmlrpc"],
                        )
                    )
            if "/plugins/" in path and code == 200 and ("Version:" in body or "stable tag" in body.lower() or "<html" in body.lower()):
                hits.append(path)

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["wordpress_deep"] = {"hits": hits}
