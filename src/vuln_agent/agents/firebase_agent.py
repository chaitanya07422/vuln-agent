from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.js_discover import script_urls
from vuln_agent.agents.secrets_patterns import FIREBASE_BUCKET, FIREBASE_PROJECT, scan_secrets
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: Firebase config → open rules / public bucket hints. No write abuse.


class FirebaseAgent(BaseAgent):
    name = "firebase"
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
        sample = "\n".join(blobs)[:1_200_000]

        secrets = scan_secrets(sample)
        fb_hits = [h for h in secrets if h["id"].startswith("firebase")]
        projects = FIREBASE_PROJECT.findall(sample)
        buckets = FIREBASE_BUCKET.findall(sample)

        if not fb_hits and not projects and not buckets:
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["firebase"] = {"skipped": True}
            return

        project = projects[0] if projects else None
        bucket = buckets[0] if buckets else None
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["firebase"] = {"project": project, "bucket": bucket}

        if project:
            # Public RTDB rules hint (read-only GET)
            rtdb = f"https://{project}-default-rtdb.firebaseio.com/.json"
            resp = await ctx.tools.http_request(method="GET", url=rtdb, max_body_bytes=8000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=rtdb, ok=resp.get("ok"))
            if resp.get("ok") and (resp.get("status_code") or 0) == 200:
                body = resp.get("body") or ""
                if body.strip() not in ("null", "") and "error" not in body.lower()[:80]:
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title="Firebase Realtime Database appears world-readable",
                            evidence_url=rtdb,
                            evidence_snippet=body[:160],
                            fix="Lock down RTDB rules; require auth for reads/writes.",
                            tags=["firebase", "rtdb"],
                        )
                    )

            firestore = (
                f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"
            )
            fs = await ctx.tools.http_request(method="GET", url=firestore, max_body_bytes=8000)
            if fs.get("ok") and (fs.get("status_code") or 0) == 200 and "documents" in (fs.get("body") or ""):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high",
                        title="Firestore documents endpoint publicly listable",
                        evidence_url=firestore,
                        evidence_snippet=(fs.get("body") or "")[:160],
                        fix="Restrict Firestore security rules; never leave open list access.",
                        tags=["firebase", "firestore"],
                    )
                )

        if bucket:
            # Storage listing probe — GET bucket root
            burl = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
            br = await ctx.tools.http_request(method="GET", url=burl, max_body_bytes=8000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=burl, ok=br.get("ok"))
            if br.get("ok") and (br.get("status_code") or 0) == 200 and "items" in (br.get("body") or ""):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high",
                        title="Firebase Storage bucket listing appears public",
                        evidence_url=burl,
                        evidence_snippet=(br.get("body") or "")[:160],
                        fix="Tighten Storage rules; disable public list; use download tokens carefully.",
                        tags=["firebase", "storage"],
                    )
                )
