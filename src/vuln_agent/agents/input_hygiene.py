from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only input hygiene: benign empty/oversize/type probes + client-only hints.
# Hard exclusions: SQLi/XSS/command payloads, sprays, authenticated crawl.

MAX_TARGETS = 15
MAX_PROBES_PER_TARGET = 3
OVERSIZE = "A" * 2500

FORM_RE = re.compile(
    r"""<form\b([^>]*)>(.*?)</form>""",
    re.I | re.S,
)
ACTION_RE = re.compile(r"""\baction=["']([^"']*)["']""", re.I)
METHOD_RE = re.compile(r"""\bmethod=["']([^"']*)["']""", re.I)
INPUT_RE = re.compile(
    r"""<(?:input|textarea|select)\b([^>]*)>""",
    re.I,
)
NAME_RE = re.compile(r"""\bname=["']([^"']+)["']""", re.I)
TYPE_RE = re.compile(r"""\btype=["']([^"']+)["']""", re.I)
REQUIRED_RE = re.compile(r"""\brequired\b""", re.I)
PATTERN_RE = re.compile(r"""\bpattern=["']([^"']+)["']""", re.I)
MAXLEN_RE = re.compile(r"""\bmaxlength=["']?(\d+)["']?""", re.I)

LEAKY_MARKERS = (
    "traceback",
    "exception",
    "stacktrace",
    "stack trace",
    "sqlstate",
    "syntax error",
    "sqlite",
    "mysql",
    "postgres",
    "mongodb",
    "ora-",
    "odbc",
    "sequelize",
    "prisma",
    "typeerror",
    "referenceerror",
    "undefined is not",
    "cannot read prop",
    "nullpointer",
    "javax.",
    "org.springframework",
    "django.",
    "werkzeug",
    "pydantic",
    "validationerror",
)

DEFAULT_API_PATHS = (
    "/api/login",
    "/api/auth/login",
    "/api/auth/signin",
    "/api/users",
    "/api/search",
    "/api/contact",
    "/api/feedback",
    "/login",
    "/contact",
    "/search",
)


def _leaky(body: str, status: int) -> Optional[str]:
    if status < 400 and status != 200:
        return None
    lower = (body or "").lower()
    for m in LEAKY_MARKERS:
        if m in lower:
            return m
    # JSON error with verbose detail
    try:
        data = json.loads(body or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    blob = json.dumps(data).lower()
    for m in ("traceback", "stack", "sql", "exception", "at line"):
        if m in blob:
            return m
    return None


def _form_targets(html: str, base: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for fm in FORM_RE.finditer(html or ""):
        attrs, inner = fm.group(1), fm.group(2)
        action_m = ACTION_RE.search(attrs)
        method_m = METHOD_RE.search(attrs)
        action = (action_m.group(1) if action_m else "") or base
        method = (method_m.group(1) if method_m else "GET").upper()
        if method not in ("GET", "POST"):
            method = "POST"
        fields: List[Dict[str, str]] = []
        client_only_hints = []
        for im in INPUT_RE.finditer(inner):
            ia = im.group(1)
            nm = NAME_RE.search(ia)
            if not nm:
                continue
            name = nm.group(1)
            typ = (TYPE_RE.search(ia).group(1) if TYPE_RE.search(ia) else "text").lower()
            if typ in ("submit", "button", "image", "file", "hidden", "checkbox", "radio"):
                if typ == "hidden":
                    continue
                if typ != "file":
                    continue
            fields.append({"name": name, "type": typ})
            if REQUIRED_RE.search(ia) or PATTERN_RE.search(ia) or MAXLEN_RE.search(ia):
                client_only_hints.append(name)
        if not fields and method == "GET":
            continue
        target = urljoin(base if base.endswith("/") else base + "/", action)
        out.append(
            {
                "url": target,
                "method": method,
                "fields": fields[:8],
                "client_hints": client_only_hints[:8],
                "source": "form",
            }
        )
        if len(out) >= MAX_TARGETS:
            break
    return out


def _api_targets(ctx: ScanContext, base: str) -> List[Dict[str, Any]]:
    paths: List[str] = []
    fp = ctx.fingerprint or {}
    for p in fp.get("js_api_paths") or []:
        if isinstance(p, str) and p.startswith("/"):
            paths.append(p.split("?")[0])
    for p in (fp.get("sitemap_crawl") or {}).get("paths") or []:
        if isinstance(p, str) and any(x in p.lower() for x in ("api", "search", "login", "contact", "form")):
            paths.append(p.split("?")[0])
    paths.extend(DEFAULT_API_PATHS)
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        out.append(
            {
                "url": urljoin(base if base.endswith("/") else base + "/", path.lstrip("/")),
                "method": "POST",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "q", "type": "text"},
                    {"name": "id", "type": "number"},
                ],
                "client_hints": [],
                "source": "api",
            }
        )
        if len(out) >= MAX_TARGETS:
            break
    return out


def _build_body(fields: List[Dict[str, str]], mode: str) -> Tuple[str, str]:
    """Return (body, content_type). Modes: empty | oversize | type_mismatch."""
    data: Dict[str, Any] = {}
    for f in fields[:6]:
        name = f["name"]
        typ = (f.get("type") or "text").lower()
        if mode == "empty":
            data[name] = ""
        elif mode == "oversize":
            data[name] = OVERSIZE if typ != "number" else "99999999999999999999"
        else:  # type_mismatch
            if typ in ("number", "range"):
                data[name] = "not-a-number"
            elif typ == "email":
                data[name] = ["not-an-email"]
            else:
                data[name] = {"nested": True}
    # Extra unexpected field
    data["_scanlead_extra"] = {"x": 1}
    return json.dumps(data), "application/json"


def _with_query(url: str, fields: List[Dict[str, str]], mode: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for f in fields[:4]:
        name = f["name"]
        if mode == "empty":
            q[name] = ""
        elif mode == "oversize":
            q[name] = OVERSIZE[:800]
        else:
            q[name] = "[]{}"
    q["_scanlead"] = "1"
    return urlunparse(parsed._replace(query=urlencode(q)))


class InputHygieneAgent(BaseAgent):
    name = "input_hygiene"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        home = await ctx.tools.http_request(method="GET", url=ctx.url, max_body_bytes=200_000)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        html = (home.get("body") or "") if home.get("ok") else ""

        targets = _form_targets(html, base)
        # Fill remaining slots with API-ish paths
        if len(targets) < MAX_TARGETS:
            for t in _api_targets(ctx, base):
                if len(targets) >= MAX_TARGETS:
                    break
                if any(x["url"] == t["url"] and x["method"] == t["method"] for x in targets):
                    continue
                targets.append(t)

        # Client-only validation notes from forms
        for t in targets:
            if t.get("client_hints"):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title=f"Form relies on HTML5 validation attributes ({t.get('source')})",
                        evidence_url=t["url"],
                        evidence_snippet=f"fields with required/pattern/maxlength: {', '.join(t['client_hints'][:5])}",
                        fix="Enforce the same constraints server-side; never trust browser-only validation.",
                        tags=["input", "client-validation"],
                    )
                )

        probed = []
        leaky_hits = []
        modes = ("empty", "oversize", "type_mismatch")

        for t in targets[:MAX_TARGETS]:
            url = t["url"]
            if not in_scope(url, ctx.scope.allow_hosts):
                continue
            method = t["method"]
            fields = t.get("fields") or [{"name": "q", "type": "text"}]
            for mode in modes[:MAX_PROBES_PER_TARGET]:
                if method == "GET":
                    probe_url = _with_query(url, fields, mode)
                    resp = await ctx.tools.http_request(method="GET", url=probe_url, max_body_bytes=12_000)
                else:
                    body, ctype = _build_body(fields, mode)
                    # Also try wrong content-type once on type_mismatch
                    headers = {"Content-Type": ctype}
                    if mode == "type_mismatch":
                        headers["Content-Type"] = "text/plain"
                    resp = await ctx.tools.http_request(
                        method=method,
                        url=url,
                        headers=headers,
                        body=body if headers["Content-Type"] != "text/plain" else "scanlead-not-json",
                        max_body_bytes=12_000,
                    )
                await ctx.audit_event(
                    agent=self.name,
                    tool="http_request",
                    url=url,
                    ok=resp.get("ok"),
                    mode=mode,
                )
                if not resp.get("ok"):
                    continue
                status = resp.get("status_code") or 0
                body_text = resp.get("body") or ""
                probed.append({"url": url, "mode": mode, "status": status})
                marker = _leaky(body_text, status)
                if marker and (url, marker) not in [(h["url"], h["marker"]) for h in leaky_hits]:
                    leaky_hits.append({"url": url, "marker": marker, "status": status, "mode": mode})
                    sev = "medium" if status >= 500 or marker in ("traceback", "sqlstate", "mysql", "postgres") else "low"
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity=sev,  # type: ignore[arg-type]
                            title=f"Verbose error on benign input probe ({mode})",
                            evidence_url=url,
                            evidence_snippet=f"HTTP {status}; marker={marker}; {(body_text or '')[:160]}",
                            fix="Validate and sanitize inputs server-side; return generic errors publicly.",
                            tags=["input", "validation", "errors"],
                        )
                    )

        # Content-Type mismatch on a single API-ish POST if not already covered
        if probed:
            sample = next((t for t in targets if t["method"] == "POST"), None)
            if sample and in_scope(sample["url"], ctx.scope.allow_hosts):
                resp = await ctx.tools.http_request(
                    method="POST",
                    url=sample["url"],
                    headers={"Content-Type": "text/plain"},
                    body="not-json",
                    max_body_bytes=8000,
                )
                if resp.get("ok"):
                    status = resp.get("status_code") or 0
                    marker = _leaky(resp.get("body") or "", status)
                    if marker:
                        await ctx.emit_finding(
                            Finding(
                                agent=self.name,
                                severity="low",
                                title="Verbose error when Content-Type is wrong",
                                evidence_url=sample["url"],
                                evidence_snippet=f"HTTP {status}; marker={marker}",
                                fix="Reject unexpected Content-Types with a generic 415/400; avoid stack details.",
                                tags=["input", "content-type"],
                            )
                        )

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["input_hygiene"] = {
            "targets": len(targets),
            "probes": len(probed),
            "leaky": len(leaky_hits),
        }
