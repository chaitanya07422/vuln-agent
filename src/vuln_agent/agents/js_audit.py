from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.js_discover import extract_api_paths, script_urls
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Deterministic patterns — no login required; catches
# Production SPA bundles are often 0.5–2MB; keywords sit past small HTTP caps.
JS_MAX_BODY = 2_500_000

PATTERNS = [
    {
        "id": "open_href_resume",
        "regex": re.compile(
            r"""href\s*:\s*(?:[A-Za-z_][\w.]*\.)?resumePath|href=\{[^}]*resumePath|"""
            r"""resumePath\s*&&[\s\S]{0,80}href\s*:""",
            re.I,
        ),
        "severity": "high",
        "title": "resumePath used directly as link href (open URL)",
        "fix": "Allowlist resume URLs to /objects/uploads/<uuid> only; reject javascript:/https: external; serve via download API.",
        "tags": ["js", "resumePath", "open-redirect"],
    },
    {
        "id": "upload_passthrough_ctype",
        "regex": re.compile(
            r"""/api/uploads?/request-url[\s\S]{0,280}contentType\s*:\s*[a-zA-Z]+\.type"""
            r"""|contentType\s*:\s*[a-zA-Z]+\.type\s*\|\|\s*["']application/octet-stream["']""",
            re.I,
        ),
        "severity": "high",
        "title": "Upload presign sends browser file.type to server (client-controlled MIME)",
        "fix": "Ignore client contentType; derive allowlisted MIME from magic bytes + extension server-side.",
        "tags": ["js", "upload", "mime"],
    },
    {
        "id": "client_only_accept",
        "regex": re.compile(
            r"""accept\s*:\s*["'][^"']*\.pdf[^"']*["']""",
            re.I,
        ),
        "severity": "medium",
        "title": "Upload accept= is client-side only (easy to bypass)",
        "fix": "Enforce the same allowlist on the server for every upload/presign request.",
        "tags": ["js", "upload", "client-validation"],
    },
    {
        "id": "objects_uploads_path",
        "regex": re.compile(
            r"""/objects/uploads/|/api/uploads/request-url|\bobjectPath\b|\buploadURL\b""",
            re.I,
        ),
        "severity": "info",
        "title": "Frontend references upload object/presign URLs",
        "fix": "Ensure /objects/uploads never serves text/html; prefer Content-Disposition: attachment.",
        "tags": ["js", "upload", "surface"],
    },
]


LLM_SYSTEM = (
    "You are a secure-code reviewer for a website JS bundle. "
    "Only report issues supported by the snippets. "
    "Do not invent endpoints. Output one finding per line: "
    "SEVERITY|short title|evidence quote (<=80 chars). "
    "SEVERITY must be high, medium, or low. Max 6 lines. No markdown."
)


class JsAuditAgent(BaseAgent):
    name = "js_audit"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        home = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if not home.get("ok"):
            return
        html = home.get("body") or ""
        bundles: List[str] = []
        api_paths: Set[str] = set()

        for script in script_urls(html, ctx.url):
            js = await ctx.tools.http_request(
                method="GET",
                url=script,
                max_body_bytes=JS_MAX_BODY,
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=script, ok=js.get("ok"))
            if not js.get("ok"):
                continue
            text = js.get("body") or ""
            if len(text) < 50:
                continue
            bundles.append(text)
            api_paths.update(extract_api_paths(text))

        if not bundles:
            return

        # Keep enough of large Vite/webpack bundles for mid-file app code
        sample = "\n".join(bundles)[:JS_MAX_BODY]
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["js_api_paths"] = sorted(api_paths)[:40]
        ctx.fingerprint["js_bundle_bytes"] = len(sample)

        matched_ids: Set[str] = set()
        for rule in PATTERNS:
            if rule["regex"].search(sample):
                matched_ids.add(rule["id"])
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity=rule["severity"],
                        title=rule["title"],
                        evidence_url=ctx.url,
                        evidence_snippet=f"Pattern {rule['id']} matched in frontend JS bundle",
                        fix=rule["fix"],
                        tags=list(rule["tags"]),
                    )
                )

        # Automatic chain  without login
        if (
            "upload_passthrough_ctype" in matched_ids
            or ("client_only_accept" in matched_ids and "objects_uploads_path" in matched_ids)
        ) and "objects_uploads_path" in matched_ids:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="Upload pipeline likely allows unsafe types + public object URLs",
                    evidence_url=urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", "api/uploads/request-url"),
                    evidence_snippet=(
                        "JS shows request-url + client MIME/accept and /objects/uploads references. "
                        "Verify server allowlists MIME and does not serve uploads as text/html."
                    ),
                    fix=(
                        "Server-side allowlist MIME/extension/size; never serve user HTML/JS/SVG "
                        "on the app origin; force attachment downloads."
                    ),
                    tags=["js", "upload", "chain"],
                )
            )

        if "open_href_resume" in matched_ids and "objects_uploads_path" in matched_ids:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="HR/user 'View Resume' can open attacker-controlled resumePath",
                    evidence_url=ctx.url,
                    evidence_snippet="JS binds href to resumePath while uploads land under object URLs",
                    fix="Validate resumePath; open via authenticated download endpoint only.",
                    tags=["js", "resumePath", "phishing"],
                )
            )

        # LLM pass over excerpts (optional)
        if ctx.llm and ctx.llm.provider_name("adapt") != "null":
            # Prefer snippets around risky keywords to stay in token budget
            excerpts = []
            for kw in ("request-url", "resumePath", "contentType", "objects/uploads", "accept:"):
                idx = sample.lower().find(kw.lower())
                if idx >= 0:
                    excerpts.append(sample[max(0, idx - 120) : idx + 220])
            if excerpts:
                prompt = (
                    f"Site: {ctx.url}\nFingerprint: {ctx.fingerprint}\n"
                    f"Known API paths: {sorted(api_paths)[:25]}\n"
                    "JS excerpts:\n" + "\n---\n".join(excerpts[:8])
                )
                try:
                    text = await ctx.llm.complete("adapt", prompt, system=LLM_SYSTEM)
                except Exception:
                    text = ""
                for line in (text or "").splitlines():
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) < 3:
                        continue
                    sev, title, evidence = parts[0].lower(), parts[1], parts[2]
                    if sev not in ("high", "medium", "low"):
                        continue
                    # anti-hallucination: evidence or title must touch known material
                    blob = (title + " " + evidence).lower()
                    if not any(
                        x in blob
                        for x in (
                            "upload",
                            "resume",
                            "presign",
                            "object",
                            "mime",
                            "href",
                            "accept",
                            "admin",
                            "auth",
                        )
                    ):
                        continue
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity=sev,  # type: ignore[arg-type]
                            title=title[:160],
                            evidence_url=ctx.url,
                            evidence_snippet=evidence[:240],
                            fix="Confirm in server code; harden upload/auth/resume handling.",
                            tags=["js", "llm"],
                        )
                    )
