from __future__ import annotations

import re
from typing import List, Tuple

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: versioned software → advisory-style notes. No exploit, no live NVD fetch required.
# Uses a small embedded map of well-known EOL / high-risk version signals.

VERSION_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"wordpress\s*[\/:]?\s*([0-4]\.\d+(?:\.\d+)?)", re.I),
        "WordPress",
        "Very old WordPress major version detected in public content — upgrade immediately.",
    ),
    (
        re.compile(r"jquery(?:\.js)?[^\d]{0,20}([12]\.\d+\.\d+)", re.I),
        "jQuery",
        "Legacy jQuery 1.x/2.x often carries known XSS issues — upgrade to a maintained release.",
    ),
    (
        re.compile(r"php/?([5-7]\.\d+(?:\.\d+)?)", re.I),
        "PHP",
        "End-of-life PHP version advertised — upgrade to a supported PHP release.",
    ),
    (
        re.compile(r"apache/?([12]\.\d+\.\d+)", re.I),
        "Apache",
        "Legacy Apache version string exposed — patch or hide Server tokens.",
    ),
    (
        re.compile(r"nginx/?(\d+\.\d+\.\d+)", re.I),
        "nginx",
        "nginx version exposed in headers/body — consider hiding version tokens and staying patched.",
    ),
    (
        re.compile(r"openssl/([01]\.\d+\.\d+[a-z]?)", re.I),
        "OpenSSL",
        "Legacy OpenSSL version string — ensure TLS stack is patched.",
    ),
    (
        re.compile(r"express(?:@|/)?(\d+\.\d+\.\d+)", re.I),
        "Express",
        "Express version visible in public assets — keep dependencies updated.",
    ),
    (
        re.compile(r"next\.js\s*v?(\d+\.\d+\.\d+)|/_next/static/([a-zA-Z0-9_-]+)", re.I),
        "Next.js",
        "Next.js surface detected — track upstream security advisories for your release line.",
    ),
]


class CveStackAgent(BaseAgent):
    name = "cve_stack"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        resp = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=150_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=resp.get("ok"))
        if not resp.get("ok"):
            return

        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        blob = " ".join(
            [
                headers.get("server") or "",
                headers.get("x-powered-by") or "",
                headers.get("x-generator") or "",
                resp.get("body") or "",
            ]
        )[:200_000]

        hits = []
        for rx, product, note in VERSION_PATTERNS:
            m = rx.search(blob)
            if not m:
                continue
            ver = next((g for g in m.groups() if g), "")
            key = f"{product}:{ver}"
            if key in hits:
                continue
            hits.append(key)
            # EOL-ish majors get medium; mere version disclosure low
            sev = "medium"
            if product in ("nginx", "Express", "Next.js") and not (
                product == "PHP" or (product == "WordPress" and ver.startswith(("3.", "4.")))
            ):
                if product in ("nginx", "Express", "Next.js"):
                    sev = "low"
            if product == "jQuery" and ver.startswith(("1.", "2.")):
                sev = "medium"
            if product == "PHP" and ver.startswith(("5.", "7.0", "7.1", "7.2", "7.3", "7.4")):
                sev = "high"
            if product == "WordPress" and ver.startswith(("3.", "4.", "5.0", "5.1", "5.2")):
                sev = "high"

            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    title=f"Version signal: {product} {ver}".strip(),
                    evidence_url=ctx.url,
                    evidence_snippet=m.group(0)[:160],
                    fix=note + " Cross-check CVEs for this version in your patch process (advisory only).",
                    tags=["cve", "supply-chain", product.lower()],
                )
            )

        # Generator meta already partially covered — still useful
        gen = re.search(
            r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
            blob,
            re.I,
        )
        if gen and not hits:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"Generator discloses stack: {gen.group(1)[:80]}",
                    evidence_url=ctx.url,
                    evidence_snippet=gen.group(0)[:160],
                    tags=["cve", "fingerprint"],
                )
            )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cve_stack"] = {"hits": hits[:12]}
