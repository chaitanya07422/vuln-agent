from __future__ import annotations

import re
from typing import Dict, Optional


_HTML_MARKERS = (
    "<!doctype html",
    "<html",
    "<head>",
    "<body",
    "<meta charset",
    "id=\"root\"",
    "id='root'",
)

_ENV_LINE = re.compile(
    r"(?m)^(?:export\s+)?[A-Z][A-Z0-9_]{1,64}\s*=\s*.+$"
)


def content_type(headers: Optional[Dict[str, str]]) -> str:
    if not headers:
        return ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def looks_like_html_document(body: str, headers: Optional[Dict[str, str]] = None) -> bool:
    """True when response is an HTML page (SPA soft-404 / catch-all)."""
    ct = content_type(headers)
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    sample = (body or "")[:2000].lower().lstrip()
    if not sample:
        return False
    return any(m in sample for m in _HTML_MARKERS)


def looks_like_dotenv(body: str) -> bool:
    """Real .env content: KEY=VALUE lines, not HTML with stray '='."""
    if looks_like_html_document(body):
        return False
    text = body or ""
    if _ENV_LINE.search(text):
        return True
    # common secret markers only when not HTML
    lower = text.lower()
    return any(
        tok in lower
        for tok in ("aws_secret", "database_url=", "db_password=", "api_key=", "private_key")
    )


def looks_like_git_head(body: str) -> bool:
    if looks_like_html_document(body):
        return False
    first = (body or "").lstrip()[:80]
    return first.startswith("ref:") or bool(re.match(r"^[0-9a-f]{40}\s*$", first, re.I))


def looks_like_binary_or_archive(headers: Optional[Dict[str, str]], body: str) -> bool:
    ct = content_type(headers)
    if any(x in ct for x in ("zip", "octet-stream", "gzip", "x-tar", "x-7z")):
        return True
    raw = body.encode("latin-1", errors="ignore")[:4] if body else b""
    # ZIP / GZIP magic
    return raw.startswith(b"PK") or raw.startswith(b"\x1f\x8b")


def reject_spa_shell_for_leak(body: str, headers: Optional[Dict[str, str]], path: str) -> bool:
    """Return True if this response should NOT raise a leak finding."""
    path_l = (path or "").lower()
    if looks_like_html_document(body, headers):
        # HTML is never a real .env / .git / zip / actuator json
        if any(
            x in path_l
            for x in (
                ".env",
                ".git",
                ".zip",
                ".sql",
                ".bak",
                "actuator",
                "swagger.json",
                "openapi.json",
                "phpinfo",
            )
        ):
            return True
        # upload/API probes that only got the marketing shell
        if any(
            x in path_l
            for x in (
                "/upload",
                "/presign",
                "/graphql",
                "/graphiql",
                "/server-status",
                "/api",
            )
        ):
            return True
    return False
