from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set

from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Friendly labels for the client summary
AGENT_LABELS = {
    "recon": "Recon & fingerprint",
    "js_audit": "Frontend JS review",
    "users": "User / author exposure",
    "auth": "Auth surfaces",
    "leaks": "Leaks & leftover files",
    "cors_api": "CORS & public APIs",
    "upload": "Upload & file routes",
    "uat_app": "Staging / UAT links",
    "ports_mail": "Ports & mail",
    "tls_headers": "TLS & security headers",
    "cloud_storage": "Cloud storage exposure",
    "admin_panels": "Admin panel surfaces",
    "email_spoof": "Email auth (SPF/DMARC)",
    "js_secrets": "Secrets in public JS",
    "sitemap_crawl": "Robots & sitemap paths",
    "graphql": "GraphQL surface",
    "websocket": "WebSocket endpoints",
    "cookie_flags": "Cookie security flags",
    "oauth_misconfig": "OAuth frontend config",
    "jwt_public": "JWKS / OIDC discovery",
    "redirect_open": "Open redirect checks",
    "http_methods": "HTTP method hygiene",
    "cors_creds": "CORS + credentials",
    "subdomain_hint": "Subdomain hints",
    "dns_hygiene": "DNS hygiene",
    "caa_dnssec": "CAA & DNSSEC",
    "cdn_origin": "CDN / origin leakage",
    "wordpress_deep": "WordPress deep checks",
    "next_react": "Next.js / React checks",
    "spring_java": "Spring actuator",
    "firebase": "Firebase exposure",
    "cache_poison_hint": "Cache poison hints",
    "rate_limit_probe": "Rate-limit probe",
    "dependency_meta": "Manifests & generator",
    "input_hygiene": "Input hygiene",
    "csrf_forms": "CSRF form hygiene",
    "access_hint": "Unauth access hints",
    "ssrf_hint": "SSRF parameter hints",
    "xss_reflect_safe": "XSS reflection (safe)",
    "auth_enum": "Auth enumeration",
    "cve_stack": "Version / CVE signals",
    "tls_depth": "TLS certificate depth",
    "adapt": "Extra path probes",
    "compliance_map": "OWASP theme map",
    "executive_brief": "Executive brief",
    "reporter": "Report",
}

# Routine noise — never show as finding cards
NOISE_TITLE_PREFIXES = (
    "recon complete",
    "server header exposed",
    "tech fingerprint",
    "dns resolves",
    "open ports:",
    "mail-related host resolves",
    "report generated",
    "wordpress license.txt",
    "unknown stack",
)


def is_noise_finding(f: Finding) -> bool:
    """Info-only chatter belongs in the summary, not finding cards."""
    if f.agent == "reporter":
        return True
    if f.severity == "info":
        return True
    title = (f.title or "").lower()
    if any(title.startswith(p) or p in title for p in NOISE_TITLE_PREFIXES):
        return True
    return False


def strip_noise_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not is_noise_finding(f)]


def _agent_issue_line(findings: List[Finding]) -> str:
    tops = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
    )
    titles = [t.title for t in tops[:2]]
    return "; ".join(titles)


def build_scan_summary(ctx: ScanContext, enabled_agents: List[str] | None = None) -> Dict[str, Any]:
    """
    Comprehensive per-agent rollup for the UI.
    'looks_solid' only when there are zero critical/high/medium/low findings after noise strip.
    """
    findings = strip_noise_findings(list(ctx.findings))
    by_agent: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_agent[f.agent].append(f)

    actionable = [f for f in findings if f.severity in ("critical", "high", "medium")]
    lows = [f for f in findings if f.severity == "low"]
    agents_run: List[str] = list(enabled_agents or [])
    if not agents_run:
        agents_run = sorted({f.agent for f in ctx.findings} | set(by_agent.keys()))
    agents_run = [a for a in agents_run if a != "reporter"]

    fp = ctx.fingerprint or {}
    tags = list(fp.get("tags") or [])
    stack = ", ".join(tags) if tags else "unknown"

    rows: List[Dict[str, str]] = []
    clean: List[str] = []
    attention: List[str] = []

    for name in agents_run:
        label = AGENT_LABELS.get(name, name)
        items = by_agent.get(name) or []
        issues = [f for f in items if f.severity in ("critical", "high", "medium", "low")]
        if issues:
            status = "attention"
            note = _agent_issue_line(issues)
            attention.append(f"{label}: {note}")
        else:
            status = "clear"
            note = _clear_note(name, fp, tags)
            clean.append(f"{label}: {note}")
        rows.append({"agent": name, "label": label, "status": status, "note": note})

    if actionable:
        verdict = "issues_found"
        headline = (
            f"Scan finished with {len(actionable)} priority issue"
            f"{'s' if len(actionable) != 1 else ''} that need attention."
        )
        all_clear = False
    elif lows:
        verdict = "minor_notes"
        headline = (
            "No major vulnerabilities in this pass; "
            f"{len(lows)} minor hygiene note{'s' if len(lows) != 1 else ''} remain."
        )
        all_clear = False
    else:
        # Only then — user asked for 100% clear bar
        verdict = "looks_solid"
        headline = (
            "Everything checked looks solid — no critical, high, medium, or low "
            "issues in this detect-only pass."
        )
        all_clear = True

    return {
        "verdict": verdict,
        "headline": headline,
        "all_clear": all_clear,
        "stack": stack,
        "agents": rows,
        "clean": clean,
        "attention": attention,
        "priority_count": len(actionable),
        "low_count": len(lows),
    }


def _clear_note(agent: str, fp: dict, tags: list) -> str:
    if agent == "recon":
        title = fp.get("title") or "site reachable"
        return f"Reachable; stack={', '.join(tags) or 'unknown'}; page={str(title)[:60]}"
    if agent == "js_audit":
        n = len(fp.get("js_api_paths") or [])
        return f"JS reviewed; no risky patterns flagged ({n} API paths noted)" if n else "JS reviewed; no risky patterns flagged"
    if agent == "upload":
        return "No confirmed upload/presign JSON API or unsafe object HTML"
    if agent == "users":
        return "No public user enumeration detected"
    if agent == "auth":
        return "No risky auth surfaces flagged"
    if agent == "leaks":
        return "No sensitive leaks confirmed"
    if agent == "cors_api":
        return "No CORS misconfig / open API docs flagged"
    if agent == "uat_app":
        return "No staging hosts linked from production"
    if agent == "ports_mail":
        return "No risky management/DB ports exposed (80/443 only is normal)"
    if agent == "adapt":
        return "Extra probes found nothing beyond expected auth walls"
    if agent == "tls_headers":
        miss = fp.get("security_headers_missing") or []
        return "Security headers reviewed" + (f" ({len(miss)} optional notes)" if miss else "")
    if agent == "email_spoof":
        em = fp.get("email_spoof") or {}
        return "SPF/DMARC/DKIM DNS reviewed"
    if agent == "js_secrets":
        return "Public JS scanned for secret patterns"
    if agent == "compliance_map":
        themes = fp.get("owasp_attention") or []
        return f"OWASP themes noted: {', '.join(themes[:3])}" if themes else "No OWASP theme hits"
    if agent == "executive_brief":
        return "Executive summary prepared"
    if agent == "input_hygiene":
        ih = fp.get("input_hygiene") or {}
        n = ih.get("probes") or 0
        return f"Benign input probes run ({n}); no leaky validation errors"
    if agent == "tls_depth":
        td = fp.get("tls_depth") or {}
        return f"TLS reviewed ({td.get('version') or 'n/a'})" if td.get("ok") else "TLS reviewed"
    if agent == "rate_limit_probe":
        rl = fp.get("rate_limit_probe") or {}
        if rl.get("skipped"):
            return "No auth-like endpoint found to probe"
        return "Auth endpoint burst checked; throttle signals present or N/A"
    if agent == "redirect_open":
        return "No confirmed external Location hop on redirect params"
    if agent in (
        "cloud_storage",
        "admin_panels",
        "sitemap_crawl",
        "graphql",
        "websocket",
        "cookie_flags",
        "oauth_misconfig",
        "jwt_public",
        "redirect_open",
        "http_methods",
        "cors_creds",
        "subdomain_hint",
        "dns_hygiene",
        "caa_dnssec",
        "cdn_origin",
        "wordpress_deep",
        "next_react",
        "spring_java",
        "firebase",
        "cache_poison_hint",
        "rate_limit_probe",
        "dependency_meta",
        "csrf_forms",
        "access_hint",
        "ssrf_hint",
        "xss_reflect_safe",
        "auth_enum",
        "cve_stack",
    ):
        block = fp.get(agent) or {}
        if isinstance(block, dict) and block.get("skipped"):
            return "Not applicable for this stack"
        return "Checked — no issues flagged"
    return "No issues flagged"
