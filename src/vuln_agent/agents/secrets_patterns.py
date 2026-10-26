from __future__ import annotations

import re
from typing import Dict, List, Pattern, Tuple

# Detect-only regexes for public JS / HTML. No live secret validation.
SECRET_RULES: List[Tuple[str, Pattern[str], str, str]] = [
    (
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "high",
        "AWS access key id pattern in public asset",
    ),
    (
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "medium",
        "Google API key pattern in public asset",
    ),
    (
        "stripe_live",
        re.compile(r"sk_live_[0-9a-zA-Z]{20,}"),
        "critical",
        "Stripe live secret key pattern in public asset",
    ),
    (
        "stripe_test",
        re.compile(r"sk_test_[0-9a-zA-Z]{20,}"),
        "low",
        "Stripe test secret key pattern in public asset",
    ),
    (
        "github_pat",
        re.compile(r"ghp_[0-9A-Za-z]{36}"),
        "high",
        "GitHub personal access token pattern in public asset",
    ),
    (
        "slack_token",
        re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
        "high",
        "Slack token pattern in public asset",
    ),
    (
        "jwt_literal",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "medium",
        "Hard-coded JWT-like string in public asset",
    ),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "critical",
        "Private key PEM block in public asset",
    ),
    (
        "firebase_api_key",
        re.compile(
            r"""apiKey["']?\s*[:=]\s*["']AIza[0-9A-Za-z_-]{20,}["']""",
            re.I,
        ),
        "medium",
        "Firebase apiKey embedded in frontend",
    ),
    (
        "firebase_config",
        re.compile(
            r"""firebase(?:app)?\.initializeApp\s*\(|messagingSenderId["']?\s*:""",
            re.I,
        ),
        "info",
        "Firebase client config present in frontend",
    ),
]


FIREBASE_PROJECT = re.compile(
    r"""projectId["']?\s*[:=]\s*["']([a-z0-9-]+)["']""",
    re.I,
)
FIREBASE_BUCKET = re.compile(
    r"""storageBucket["']?\s*[:=]\s*["']([^"']+)["']""",
    re.I,
)
WS_URL = re.compile(
    r"""["'](wss?://[^"'\s]+)["']|new\s+WebSocket\s*\(\s*["']([^"']+)["']""",
    re.I,
)
OAUTH_REDIRECT = re.compile(
    r"""redirect_uri\s*=\s*([^&\s"']+)|redirectUri["']?\s*[:=]\s*["']([^"']+)["']""",
    re.I,
)
CLIENT_SECRET_JS = re.compile(
    r"""(?:client_secret|clientSecret)\s*[:=]\s*["']([^"']{8,})["']""",
    re.I,
)
MISSING_STATE = re.compile(
    r"""(?:oauth|authorize)[^"']{0,80}(?:response_type\s*=\s*code)(?![^"']{0,120}\bstate\b)""",
    re.I,
)


def scan_secrets(text: str, *, max_hits: int = 12) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    seen = set()
    for rid, rx, sev, title in SECRET_RULES:
        if rid in seen:
            continue
        m = rx.search(text or "")
        if not m:
            continue
        seen.add(rid)
        snippet = m.group(0)[:80]
        # Redact middle of long secrets
        if len(snippet) > 16:
            snippet = snippet[:8] + "…" + snippet[-4:]
        hits.append(
            {
                "id": rid,
                "severity": sev,
                "title": title,
                "snippet": snippet,
            }
        )
        if len(hits) >= max_hits:
            break
    return hits
