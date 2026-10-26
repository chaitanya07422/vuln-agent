from __future__ import annotations

from urllib.parse import urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: HEAD/GET common public object URL shapes. No bucket enumeration flood.


class CloudStorageAgent(BaseAgent):
    name = "cloud_storage"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        host = (urlparse(ctx.url).hostname or "").lower()
        if not host:
            return
        # Derive likely bucket-style names from apex
        apex = host[4:] if host.startswith("www.") else host
        short = apex.split(".")[0]
        candidates = [
            f"https://{apex}.s3.amazonaws.com/",
            f"https://{short}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{short}/",
            f"https://storage.googleapis.com/{short}/",
            f"https://{short}.storage.googleapis.com/",
            f"https://{short}.blob.core.windows.net/",
            f"https://{apex}.blob.core.windows.net/",
        ]
        # Also probe paths on origin that often proxy public storage
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        origin_paths = [
            "static/",
            "uploads/",
            "media/",
            "assets/uploads/",
        ]

        hits = []
        for url in candidates[:6]:
            resp = await ctx.tools.http_request(method="GET", url=url, max_body_bytes=8000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=url, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            code = resp.get("status_code") or 0
            body = (resp.get("body") or "").lower()
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            listing = (
                code == 200
                and (
                    "<listbucketresult" in body
                    or "<enumerationresults" in body
                    or "blob.core.windows.net" in body
                    or ("<key>" in body and "s3" in body)
                )
            )
            # Public list / open ACL hints
            if listing or (code == 200 and "x-amz-request-id" in headers and "accessdenied" not in body):
                if listing or ("listbucket" in body or "contents>" in body):
                    hits.append(url)
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title="Cloud storage bucket appears publicly listable",
                            evidence_url=url,
                            evidence_snippet=(resp.get("body") or "")[:180],
                            fix="Block public listing; use signed URLs and private ACLs.",
                            tags=["cloud", "storage", "exposure"],
                        )
                    )

        for path in origin_paths:
            from urllib.parse import urljoin

            target = urljoin(base, path)
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=6000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            body = (resp.get("body") or "").lower()
            code = resp.get("status_code") or 0
            if code == 200 and ("index of /" in body or "<title>directory listing" in body):
                hits.append(target)
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="Directory listing enabled on upload/static path",
                        evidence_url=target,
                        evidence_snippet=(resp.get("body") or "")[:160],
                        fix="Disable autoindex; serve files via app with auth when needed.",
                        tags=["cloud", "listing"],
                    )
                )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["cloud_storage"] = {"hits": hits[:8]}
