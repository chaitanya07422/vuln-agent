from __future__ import annotations

import re
from typing import List, Set, Tuple

from vuln_agent.core.finding import Finding

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm_title(title: str) -> str:
    t = (title or "").lower()
    t = re.sub(r"https?://\S+", "", t)
    t = re.sub(r"/[a-z0-9_./-]{3,}", " ", t)
    t = re.sub(r"[^a-z0-9\s]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _overlap_key(f: Finding) -> str:
    """Group near-duplicate findings for collapse."""
    title = (f.title or "").lower()
    tags = set(f.tags or [])
    agent = f.agent

    if agent == "js_audit" and (
        "resumepath" in title or ("resume" in title and ("href" in title or "view" in title or "open" in title))
    ):
        return "js:resume_href"
    if agent == "js_audit" and (
        "mime" in title
        or "contenttype" in title.replace(" ", "")
        or "file.type" in title
        or "accept=" in title
        or "octet-stream" in title
        or "metadata" in title
        or ("upload" in title and ("pipeline" in title or "presign" in title or "unsafe" in title))
        or "client-controlled" in title
        or "client only" in title
        or "client-side" in title
    ):
        return "js:upload_mime"
    if agent == "js_audit" and ("object" in title or "presign" in title or "request-url" in title):
        if "pipeline" in title or "mime" in title:
            return "js:upload_mime"
        return "js:upload_surface"
    if agent == "upload" and ("presign" in title or "request-url" in title or "upload/" in title):
        return "http:upload_presign"
    if agent == "upload" and ("object" in title or "/objects/" in title):
        return "http:upload_objects"
    if agent == "adapt" and title.startswith("protected api responds"):
        return "adapt:protected_apis"
    if agent == "adapt" and title.startswith("public api responds"):
        return "adapt:public_apis"
    if "phishing" in tags and "resume" in title:
        return "js:resume_href"
    if "chain" in tags and "upload" in tags:
        return "js:upload_mime"
    return f"{agent}:{_norm_title(f.title)}"


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Keep strongest unique signal; merge adapt protected-API paths into one card."""
    buckets: dict[str, List[Finding]] = {}
    order: List[str] = []
    for f in findings:
        if f.agent == "reporter":
            key = f"reporter:{id(f)}"
        else:
            key = _overlap_key(f)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(f)

    out: List[Finding] = []
    for key in order:
        group = buckets[key]
        if key == "adapt:protected_apis" and len(group) > 1:
            out.append(_merge_adapt_protected(group))
            continue
        if key == "adapt:public_apis" and len(group) > 1:
            out.append(_merge_adapt_public(group))
            continue
        # Prefer higher severity, then longer explanation, then longer evidence
        group.sort(
            key=lambda x: (
                SEVERITY_RANK.get(x.severity, 9),
                0 if x.explanation else 1,
                -(len(x.evidence_snippet or "")),
                -(len(x.title or "")),
            )
        )
        out.append(group[0])
    return out


def _merge_adapt_protected(group: List[Finding]) -> Finding:
    paths: List[str] = []
    snippets: List[str] = []
    for f in group:
        m = re.search(r"(GET|POST|PUT|DELETE)\s+(/\S+)", f.title or "", re.I)
        if m:
            paths.append(f"{m.group(1).upper()} {m.group(2)}")
        elif f.evidence_url:
            paths.append(f.evidence_url)
        if f.evidence_snippet:
            snippets.append(f.evidence_snippet[:120])
    paths = list(dict.fromkeys(paths))[:12]
    return Finding(
        agent="adapt",
        severity="medium",
        title=f"Protected APIs respond (auth required): {len(paths)} endpoints",
        evidence_url=group[0].evidence_url,
        evidence_snippet="; ".join(paths) + (f" | e.g. {snippets[0]}" if snippets else ""),
        explanation=group[0].explanation,
        fix=(
            "Expected for private APIs. Confirm each route requires auth, "
            "avoids verbose errors, and is not meant to be public."
        ),
        tags=["adapt", "probe", "auth"],
    )


def _merge_adapt_public(group: List[Finding]) -> Finding:
    paths = []
    for f in group:
        m = re.search(r"(GET|POST)\s+(/\S+)", f.title or "", re.I)
        if m:
            paths.append(f"{m.group(1).upper()} {m.group(2)}")
    paths = list(dict.fromkeys(paths))[:12]
    return Finding(
        agent="adapt",
        severity="info",
        title=f"Public APIs respond: {len(paths)} endpoints",
        evidence_url=group[0].evidence_url,
        evidence_snippet="; ".join(paths),
        fix="Review whether each public API should stay unauthenticated.",
        tags=["adapt", "probe", "public"],
    )
