from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: robots + sitemap discovery; capped HEAD/GET (max 40 paths).

LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
SITEMAP_RE = re.compile(r"(?im)^sitemap:\s*(\S+)")
DISALLOW_RE = re.compile(r"(?im)^disallow:\s*(\S+)")
MAX_PATHS = 40


class SitemapCrawlAgent(BaseAgent):
    name = "sitemap_crawl"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        robots_url = urljoin(base, "robots.txt")
        robots = await ctx.tools.http_request(method="GET", url=robots_url, max_body_bytes=50_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=robots_url, ok=robots.get("ok"))

        sitemap_urls: List[str] = []
        interesting_disallow: List[str] = []
        if robots.get("ok") and (robots.get("status_code") or 0) == 200:
            text = robots.get("body") or ""
            for m in SITEMAP_RE.finditer(text):
                sitemap_urls.append(m.group(1).strip())
            for m in DISALLOW_RE.finditer(text):
                path = m.group(1).strip()
                if any(x in path.lower() for x in ("admin", "api", "backup", "private", "internal", "debug", ".env", "wp-admin")):
                    interesting_disallow.append(path)

        if not sitemap_urls:
            sitemap_urls = [urljoin(base, "sitemap.xml"), urljoin(base, "sitemap_index.xml")]

        paths: Set[str] = set()
        for sm_url in sitemap_urls[:4]:
            if not in_scope(sm_url, ctx.scope.allow_hosts) and urlparse(sm_url).hostname:
                # allow absolute sitemaps on same registrable host via in_scope
                if not in_scope(sm_url, ctx.scope.allow_hosts):
                    continue
            sm = await ctx.tools.http_request(method="GET", url=sm_url, max_body_bytes=200_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=sm_url, ok=sm.get("ok"))
            if not sm.get("ok"):
                continue
            body = sm.get("body") or ""
            # nested sitemap index
            for m in LOC_RE.finditer(body):
                loc = m.group(1).strip()
                if loc.endswith(".xml") and len(sitemap_urls) < 6:
                    sitemap_urls.append(loc)
                else:
                    path = urlparse(loc).path or "/"
                    if path and path != "/":
                        paths.add(path)
                if len(paths) >= MAX_PATHS:
                    break

        probed = []
        sensitive_hits = []
        for path in sorted(paths)[:MAX_PATHS]:
            target = urljoin(base, path.lstrip("/"))
            if not in_scope(target, ctx.scope.allow_hosts):
                continue
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=4000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            probed.append(path)
            lower_path = path.lower()
            if code == 200 and any(
                x in lower_path for x in ("admin", "backup", "internal", "debug", "staging", "private", ".sql", ".bak")
            ):
                sensitive_hits.append(path)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title=f"Sensitive-looking path listed in sitemap: {path}",
                        evidence_url=target,
                        evidence_snippet=f"HTTP {code} from sitemap discovery",
                        fix="Remove sensitive URLs from public sitemaps; restrict access.",
                        tags=["sitemap", "exposure"],
                    )
                )

        for path in interesting_disallow[:5]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title=f"robots.txt Disallow hints sensitive path: {path}",
                    evidence_url=robots_url,
                    evidence_snippet=path,
                    tags=["robots"],
                )
            )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["sitemap_crawl"] = {
            "paths": probed[:40],
            "disallow_hints": interesting_disallow[:10],
            "sensitive": sensitive_hits[:10],
        }
