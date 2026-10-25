from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin
from uuid import uuid4

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.content_guards import looks_like_html_document
from vuln_agent.agents.js_discover import extract_api_paths, extract_object_upload_urls, script_urls
from vuln_agent.agents.playbook_runner import run_http_steps
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

PRESIGN_CANDIDATES = [
    "/api/uploads/request-url",
    "/api/upload/request-url",
    "/api/uploads/presign",
    "/api/presign",
    "/api/files/presign",
]

OBJECT_PREFIXES = [
    "/objects/uploads/",
    "/uploads/",
    "/files/",
    "/media/uploads/",
]


def _homepage_sig(body: str, headers: Dict[str, str]) -> Dict[str, Any]:
    title_m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:120] if title_m else ""
    raw = (body or "").encode("utf-8", errors="ignore")
    return {
        "length": len(raw),
        "sha12": hashlib.sha256(raw).hexdigest()[:12],
        "title": title,
        "content_type": (headers or {}).get("content-type")
        or (headers or {}).get("Content-Type")
        or "",
    }


def _is_spa_shell(body: str, headers: Dict[str, str], home: Optional[Dict[str, Any]]) -> bool:
    if not looks_like_html_document(body, headers):
        return False
    if not home:
        # generic SPA markers
        low = (body or "").lower()
        return 'id="root"' in low or "id='root'" in low or "/assets/index-" in low
    sig = _homepage_sig(body, headers)
    if home.get("sha12") and sig["sha12"] == home.get("sha12"):
        return True
    if home.get("length") and abs(sig["length"] - int(home["length"])) <= 32:
        if sig.get("title") and sig.get("title") == home.get("title"):
            return True
    return False


class UploadAgent(BaseAgent):
    name = "upload"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        # Keep YAML steps (now SPA-safe)
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        steps = ctx.playbooks.section(tags, "upload") if ctx.playbooks else []
        await run_http_steps(ctx, agent_name=self.name, steps=steps)

        home_resp = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home_resp.get("ok"))
        home_body = home_resp.get("body") or ""
        home_headers = home_resp.get("headers") or {}
        home_sig = _homepage_sig(home_body, home_headers) if home_resp.get("ok") else {}
        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["homepage_sig"] = home_sig

        discovered: Set[str] = set(PRESIGN_CANDIDATES)
        object_samples: List[str] = []

        for script in script_urls(home_body, ctx.url):
            js = await ctx.tools.http_request(method="GET", url=script)
            await ctx.audit_event(agent=self.name, tool="http_request", url=script, ok=js.get("ok"))
            if not js.get("ok"):
                continue
            text = js.get("body") or ""
            for p in extract_api_paths(text):
                discovered.add(p)
            object_samples.extend(extract_object_upload_urls(text))

        # 1) Presign / upload API probes (JSON only — not SPA HTML)
        probed_presign = False
        for path in sorted(discovered):
            if "upload" not in path.lower() and "presign" not in path.lower() and "file" not in path.lower():
                continue
            if path.count("/") < 2:
                continue
            target = urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", path.lstrip("/"))
            # Prefer POST for request-url style endpoints
            method = "POST" if "request" in path or "presign" in path or path.endswith("upload") else "GET"
            body = None
            headers = {"Accept": "application/json"}
            if method == "POST":
                headers["Content-Type"] = "application/json"
                body = json.dumps(
                    {
                        "name": "resume.pdf",
                        "size": 1024,
                        "contentType": "application/pdf",
                        "content_type": "application/pdf",
                    }
                )
            resp = await ctx.tools.http_request(method=method, url=target, headers=headers, body=body)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok"):
                continue
            status = resp.get("status_code")
            rbody = resp.get("body") or ""
            rheaders = resp.get("headers") or {}
            if _is_spa_shell(rbody, rheaders, home_sig):
                continue
            ct = (rheaders.get("content-type") or rheaders.get("Content-Type") or "").lower()
            is_json = "json" in ct or rbody.strip().startswith("{") or rbody.strip().startswith("[")
            if not is_json and status not in (401, 403):
                continue

            probed_presign = True
            lower = rbody.lower()
            if status in (401, 403) or "log in" in lower or "login" in lower or "unauthorized" in lower:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"Upload/presign API present (auth required): {path}",
                        evidence_url=target,
                        evidence_snippet=f"HTTP {status}; {rbody[:240]}",
                        fix="Keep auth; enforce server-side MIME/extension/size allowlists; never serve uploads as HTML.",
                        tags=["upload", "presign", "api"],
                    )
                )
            elif status == 200 and is_json:
                # Unauthenticated presign success = critical
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="critical",
                        title=f"Unauthenticated upload/presign API: {path}",
                        evidence_url=target,
                        evidence_snippet=f"HTTP {status}; {rbody[:240]}",
                        fix="Require authentication for upload presign; allowlist file types server-side.",
                        tags=["upload", "presign", "unauth"],
                    )
                )

        if not probed_presign:
            # still try canonical path
            path = "/api/uploads/request-url"
            target = urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", path.lstrip("/"))
            resp = await ctx.tools.http_request(
                method="POST",
                url=target,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                body='{"name":"resume.pdf","size":1,"contentType":"application/pdf"}',
            )
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            rbody = resp.get("body") or ""
            if resp.get("ok") and not _is_spa_shell(rbody, resp.get("headers") or {}, home_sig):
                status = resp.get("status_code")
                if status in (401, 403) or "log in" in rbody.lower():
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="medium",
                            title="Upload/presign API present (auth required): /api/uploads/request-url",
                            evidence_url=target,
                            evidence_snippet=f"HTTP {status}; {rbody[:240]}",
                            fix="Keep auth; enforce MIME/size allowlists; don't serve user HTML on the app origin.",
                            tags=["upload", "presign", "api"],
                        )
                    )

        # 2) Object serve route: missing UUID → JSON 404 proves route; non-SPA HTML → critical
        for prefix in OBJECT_PREFIXES:
            missing = urljoin(
                ctx.url if ctx.url.endswith("/") else ctx.url + "/",
                f"{prefix.lstrip('/')}{uuid4()}",
            )
            miss = await ctx.tools.http_request(method="GET", url=missing)
            await ctx.audit_event(agent=self.name, tool="http_request", url=missing, ok=miss.get("ok"))
            if not miss.get("ok"):
                continue
            mbody = miss.get("body") or ""
            mheaders = miss.get("headers") or {}
            mstatus = miss.get("status_code")
            mct = (mheaders.get("content-type") or "").lower()
            if mstatus == 404 and ("json" in mct or mbody.strip().startswith("{")):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"User-object URL route exists: {prefix}<uuid>",
                        evidence_url=missing,
                        evidence_snippet=f"HTTP {mstatus}; {mbody[:200]}",
                        fix="Auth-gate object URLs or force Content-Disposition: attachment; never text/html for uploads.",
                        tags=["upload", "objects", "route"],
                    )
                )
                # Only need one confirmed object route prefix
                break

        # 3) Any concrete object URLs discovered in JS (or known live objects)
        for path in object_samples[:5]:
            await self._check_object_html(ctx, path, home_sig)

        # Also check careers page HTML for object links
        careers = urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", "careers")
        c_resp = await ctx.tools.http_request(method="GET", url=careers)
        if c_resp.get("ok"):
            for path in extract_object_upload_urls(c_resp.get("body") or "")[:5]:
                await self._check_object_html(ctx, path, home_sig)

    async def _check_object_html(self, ctx: ScanContext, path: str, home_sig: Dict[str, Any]) -> None:
        target = urljoin(ctx.url if ctx.url.endswith("/") else ctx.url + "/", path.lstrip("/"))
        resp = await ctx.tools.http_request(method="GET", url=target)
        await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
        if not resp.get("ok") or resp.get("status_code") != 200:
            return
        body = resp.get("body") or ""
        headers = resp.get("headers") or {}
        if _is_spa_shell(body, headers, home_sig):
            return
        if looks_like_html_document(body, headers):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="critical",
                    title="Public HTML served from upload/object URL",
                    evidence_url=target,
                    evidence_snippet=f"HTTP 200; content-type HTML; not the SPA shell; len={len(body)}",
                    fix="Do not serve user uploads as text/html on the app domain; use attachment + allowlisted MIME.",
                    tags=["upload", "public-html", "phishing"],
                )
            )
