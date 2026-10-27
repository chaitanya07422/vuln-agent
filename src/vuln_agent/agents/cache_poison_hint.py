from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: unkeyed header reflection (Host / X-Forwarded-*). No poison delivery.


def response_looks_cacheable(headers: dict) -> bool:
    """True only when intermediate caches might store the response."""
    cc = (headers.get("cache-control") or "").lower()
    pragma = (headers.get("pragma") or "").lower()
    if "no-store" in cc or "no-cache" in cc or "private" in cc:
        return False
    if "no-cache" in pragma:
        return False
    # Explicit zero / must-revalidate with max-age=0 → not a poison store
    if "max-age=0" in cc.replace(" ", ""):
        return False
    # Surrogate / CDN hints that still say miss+uncacheable are handled via CC above
    return True


class CachePoisonHintAgent(BaseAgent):
    name = "cache_poison_hint"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        marker = f"scanlead-cph-{ctx.scan_id[:8] if ctx.scan_id else 'x'}.invalid"
        probes = [
            {"X-Forwarded-Host": marker},
            {"X-Forwarded-Scheme": "nothttps"},
            {"X-Original-URL": "/scanlead-poison-check"},
            {"X-Rewrite-URL": "/scanlead-poison-check"},
        ]
        hits = []
        for headers in probes:
            resp = await ctx.tools.http_request(
                method="GET",
                url=ctx.url,
                headers=headers,
                max_body_bytes=30_000,
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            body = resp.get("body") or ""
            resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            blob = body + " " + " ".join(resp_headers.values())
            key = next(iter(headers))
            if marker in blob or "scanlead-poison-check" in blob or marker in (resp.get("url") or ""):
                hits.append(key)
                cacheable = response_looks_cacheable(resp_headers)
                if cacheable:
                    sev = "medium"
                    fix = (
                        "Do not trust X-Forwarded-* / Host overrides from clients; "
                        "configure trusted proxy hops only; vary/cache keys must not include unkeyed headers."
                    )
                    title = f"Unkeyed header reflection: {key}"
                else:
                    sev = "info"
                    fix = (
                        "Header value is reflected but this response is not cacheable "
                        "(no-store/no-cache/private). Strip untrusted X-Forwarded-* at the edge anyway."
                    )
                    title = f"Untrusted header reflected (not cacheable): {key}"
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        title=title,
                        evidence_url=ctx.url,
                        evidence_snippet=f"{key} value reflected in response"
                        + ("" if cacheable else "; Cache-Control prevents store"),
                        fix=fix,
                        tags=["cache", "headers"] + ([] if cacheable else ["hygiene"]),
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cache_poison_hint"] = {"hits": hits}
