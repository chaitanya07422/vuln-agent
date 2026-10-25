from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

HeaderMap = Dict[str, str]
Rule = Tuple[Callable[[HeaderMap, str], bool], str]

# Add tech: append a rule + (later) a playbook YAML. No agent rewrite needed.
RULES: List[Rule] = [
    (
        lambda h, html: "wp-json" in html.lower()
        or "wordpress" in html.lower()
        or "wp-content" in html.lower(),
        "wordpress",
    ),
    (
        lambda h, html: "/_next/" in html or "next-route" in html.lower(),
        "nextjs",
    ),
    (
        lambda h, html: "x-powered-by" in {k.lower() for k in h}
        and "express" in h.get("x-powered-by", h.get("X-Powered-By", "")).lower(),
        "express",
    ),
    (
        lambda h, html: "nestjs" in html.lower() or "nest.js" in html.lower(),
        "nestjs",
    ),
    (
        lambda h, html: "shopify" in html.lower() or "cdn.shopify.com" in html.lower(),
        "shopify",
    ),
    (
        lambda h, html: bool(re.search(r"cloudflare|cf-ray", " ".join(h.keys()).lower() + " ".join(h.values()).lower())),
        "cloudflare",
    ),
]


def fingerprint(headers: HeaderMap, html: str) -> Dict[str, object]:
    # Normalize header keys for rule checks while keeping originals in output
    lower_headers = {k.lower(): v for k, v in headers.items()}
    tags: List[str] = []
    for rule, tag in RULES:
        try:
            if rule(lower_headers, html or "") and tag not in tags:
                tags.append(tag)
        except Exception:
            continue

    server = lower_headers.get("server")
    powered = lower_headers.get("x-powered-by")

    if not tags:
        tags.append("unknown")

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    title = title_match.group(1).strip() if title_match else None
    if title:
        title = re.sub(r"\s+", " ", title)[:200]

    return {
        "tags": tags,
        "server": server,
        "powered_by": powered,
        "title": title,
    }
