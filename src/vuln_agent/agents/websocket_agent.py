from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.js_discover import script_urls
from vuln_agent.agents.secrets_patterns import WS_URL
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: collect ws/wss URLs from HTML/JS; connectivity note via HTTP upgrade hint only.


class WebsocketAgent(BaseAgent):
    name = "websocket"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        home = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if not home.get("ok"):
            return

        blobs = [home.get("body") or ""]
        for script in script_urls(home.get("body") or "", ctx.url)[:8]:
            js = await ctx.tools.http_request(method="GET", url=script, max_body_bytes=800_000)
            if js.get("ok") and js.get("body"):
                blobs.append(js["body"])

        urls = []
        for blob in blobs:
            for m in WS_URL.finditer(blob):
                u = m.group(1) or m.group(2)
                if u and u not in urls:
                    urls.append(u)
                if len(urls) >= 8:
                    break

        # HTTP probe of same-origin socket.io / ws paths (not a real WS handshake flood)
        from urllib.parse import urljoin

        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        for path in ("/socket.io/", "/ws", "/websocket", "/_next/webpack-hmr"):
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=2000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            if code in (101, 200, 400) and (
                "websocket" in (headers.get("upgrade") or "").lower()
                or "socket.io" in (resp.get("body") or "").lower()
                or path in ("/socket.io/", "/ws")
                and code != 404
            ):
                if path not in [urlparse_path(u) for u in urls]:
                    urls.append(target)

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["websocket"] = {"urls": urls[:8]}

        for u in urls[:5]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="WebSocket endpoint referenced",
                    evidence_url=u if u.startswith("http") else ctx.url,
                    evidence_snippet=u[:200],
                    tags=["websocket"],
                )
            )
            # Flag cleartext ws://
            if u.startswith("ws://"):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="Cleartext WebSocket (ws://) referenced",
                        evidence_url=ctx.url,
                        evidence_snippet=u[:200],
                        fix="Use wss:// only; terminate TLS at the edge.",
                        tags=["websocket", "tls"],
                    )
                )


def urlparse_path(u: str) -> str:
    from urllib.parse import urlparse

    return urlparse(u).path or u
