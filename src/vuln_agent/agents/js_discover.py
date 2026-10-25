from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin

SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
API_PATH = re.compile(
    r"""["'`](/api/[a-zA-Z0-9_./-]{3,80})["'`]"""
)
OBJECT_PATH = re.compile(
    r"""["'`](/objects/uploads/[a-f0-9-]{36})["'`]"""
)
UPLOAD_HINT = re.compile(
    r"""["'`](/(?:api/)?(?:uploads?|presign|files?)[a-zA-Z0-9_./-]*)["'`]"""
)


def script_urls(html: str, base_url: str) -> List[str]:
    out: List[str] = []
    for m in SCRIPT_SRC.finditer(html or ""):
        src = m.group(1)
        if src.startswith("data:"):
            continue
        out.append(urljoin(base_url, src))
    return out[:12]


def extract_api_paths(js_text: str) -> List[str]:
    found: Set[str] = set()
    for rx in (API_PATH, UPLOAD_HINT):
        for m in rx.finditer(js_text or ""):
            path = m.group(1)
            if path.startswith("/api/") or "upload" in path.lower() or "presign" in path.lower():
                found.add(path.split("?")[0])
    return sorted(found)[:40]


def extract_object_upload_urls(js_text: str) -> List[str]:
    return sorted({m.group(1) for m in OBJECT_PATH.finditer(js_text or "")})[:20]
