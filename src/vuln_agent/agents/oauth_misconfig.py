from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.js_discover import script_urls
from vuln_agent.agents.secrets_patterns import CLIENT_SECRET_JS, OAUTH_REDIRECT
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: frontend OAuth redirect_uri / client_secret in JS. No token exchange.


class OauthMisconfigAgent(BaseAgent):
    name = "oauth_misconfig"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        home = await ctx.tools.http_request(method="GET", url=ctx.url)
        await ctx.audit_event(agent=self.name, tool="http_request", url=ctx.url, ok=home.get("ok"))
        if not home.get("ok"):
            return

        blobs = [home.get("body") or ""]
        for script in script_urls(home.get("body") or "", ctx.url)[:10]:
            js = await ctx.tools.http_request(method="GET", url=script, max_body_bytes=1_000_000)
            if js.get("ok") and js.get("body"):
                blobs.append(js["body"])
        sample = "\n".join(blobs)[:1_500_000]

        redirects = []
        for m in OAUTH_REDIRECT.finditer(sample):
            val = (m.group(1) or m.group(2) or "").strip()
            if val and val not in redirects:
                redirects.append(val[:300])

        secrets = list(CLIENT_SECRET_JS.finditer(sample))
        has_oauth = "oauth" in sample.lower() or "authorize" in sample.lower() or bool(redirects)

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["oauth_misconfig"] = {
            "redirects": redirects[:8],
            "client_secret_in_js": bool(secrets),
        }

        for s in secrets[:2]:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title="OAuth client_secret embedded in frontend JS",
                    evidence_url=ctx.url,
                    evidence_snippet="client_secret/clientSecret assignment in public bundle",
                    fix="Never ship client secrets to browsers; use confidential server-side clients or PKCE public clients.",
                    tags=["oauth", "secrets"],
                )
            )

        for r in redirects[:5]:
            lower = r.lower()
            if "localhost" in lower or "127.0.0.1" in lower or lower.startswith("http://"):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title="OAuth redirect_uri looks insecure or local",
                        evidence_url=ctx.url,
                        evidence_snippet=r[:200],
                        fix="Register only HTTPS production redirect URIs; remove localhost from prod config.",
                        tags=["oauth", "redirect"],
                    )
                )
            elif "*" in r or lower.endswith("/") is False and "redirect" in sample.lower():
                # open-ended redirect patterns
                if "javascript:" in lower or lower in ("", "null", "undefined"):
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="high",
                            title="Suspicious OAuth redirect_uri value",
                            evidence_url=ctx.url,
                            evidence_snippet=r[:200],
                            fix="Allowlist exact redirect URIs server-side.",
                            tags=["oauth", "redirect"],
                        )
                    )

        if has_oauth and "state=" not in sample.lower() and "state:" not in sample.lower():
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="low",
                    title="OAuth flow may omit CSRF state parameter",
                    evidence_url=ctx.url,
                    evidence_snippet="oauth/authorize references without obvious state usage",
                    fix="Include and validate a high-entropy state (and PKCE for public clients).",
                    tags=["oauth", "csrf"],
                )
            )
