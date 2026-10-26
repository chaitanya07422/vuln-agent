from __future__ import annotations

from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import in_scope
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: login/reset message or status differentials. No password sprays.

LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/api/login",
    "/api/auth/login",
    "/api/auth/signin",
    "/wp-login.php",
    "/accounts/login",
)
RESET_PATHS = (
    "/forgot-password",
    "/password/reset",
    "/api/password/forgot",
    "/api/auth/forgot-password",
    "/wp-login.php?action=lostpassword",
)

EXISTING = "admin@example.com"
MISSING = "scanlead-no-such-user-9f2c@invalid.example"


class AuthEnumAgent(BaseAgent):
    name = "auth_enum"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        login_url = None
        for path in LOGIN_PATHS:
            u = urljoin(base, path.lstrip("/"))
            if not in_scope(u, ctx.scope.allow_hosts):
                continue
            r = await ctx.tools.http_request(method="GET", url=u, max_body_bytes=8000)
            if r.get("ok") and (r.get("status_code") or 0) not in (404, 410):
                login_url = u
                break
        if not login_url:
            login_url = ctx.url

        # Two login attempts with different identities — same password dummy
        a = await self._post_creds(ctx, login_url, EXISTING)
        b = await self._post_creds(ctx, login_url, MISSING)

        enum_login = False
        if a and b:
            if a["status"] != b["status"]:
                enum_login = True
            elif _normalize(a["body"]) != _normalize(b["body"]) and abs(len(a["body"]) - len(b["body"])) > 8:
                enum_login = True

        reset_url = None
        for path in RESET_PATHS:
            u = urljoin(base, path.lstrip("/"))
            if not in_scope(u, ctx.scope.allow_hosts):
                continue
            r = await ctx.tools.http_request(method="GET", url=u, max_body_bytes=8000)
            if r.get("ok") and (r.get("status_code") or 0) not in (404, 410):
                reset_url = u
                break

        enum_reset = False
        if reset_url:
            ra = await self._post_reset(ctx, reset_url, EXISTING)
            rb = await self._post_reset(ctx, reset_url, MISSING)
            if ra and rb:
                if ra["status"] != rb["status"] or (
                    _normalize(ra["body"]) != _normalize(rb["body"])
                    and abs(len(ra["body"]) - len(rb["body"])) > 8
                ):
                    enum_reset = True

        # MFA hint from login page
        login_get = await ctx.tools.http_request(method="GET", url=login_url, max_body_bytes=30_000)
        page = ((login_get.get("body") or "") if login_get.get("ok") else "").lower()
        mentions_mfa = any(x in page for x in ("mfa", "2fa", "two-factor", "otp", "authenticator"))

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["auth_enum"] = {
            "login_url": login_url,
            "reset_url": reset_url,
            "enum_login": enum_login,
            "enum_reset": enum_reset,
            "mfa_mentioned": mentions_mfa,
        }

        if enum_login:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="Login responses differ by account existence (user enumeration)",
                    evidence_url=login_url,
                    evidence_snippet=f"status A={a and a['status']} B={b and b['status']}; body lengths differ",
                    fix="Return identical messages and status codes for invalid credentials regardless of whether the user exists.",
                    tags=["auth", "enum"],
                )
            )
        if enum_reset:
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="Password-reset responses leak account existence",
                    evidence_url=reset_url or ctx.url,
                    evidence_snippet="Different status/body for existing vs non-existing emails",
                    fix="Always show a generic 'If the account exists, we sent email' response.",
                    tags=["auth", "enum", "reset"],
                )
            )
        if login_get.get("ok") and not mentions_mfa and any(
            x in page for x in ("password", "sign in", "log in")
        ):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="info",
                    title="No MFA/2FA cues on login surface",
                    evidence_url=login_url,
                    evidence_snippet="Login page text lacks MFA/2FA/OTP markers",
                    tags=["auth", "mfa"],
                )
            )

    async def _post_creds(self, ctx: ScanContext, url: str, email: str):
        body = f'{{"email":"{email}","username":"{email}","password":"ScanleadCheck1!"}}'
        resp = await ctx.tools.http_request(
            method="POST",
            url=url,
            headers={"Content-Type": "application/json"},
            body=body,
            max_body_bytes=8000,
        )
        await ctx.audit_event(agent=self.name, tool="http_request", url=url, ok=resp.get("ok"))
        if not resp.get("ok"):
            # form-encoded fallback
            resp = await ctx.tools.http_request(
                method="POST",
                url=url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=f"email={email}&username={email}&password=ScanleadCheck1!",
                max_body_bytes=8000,
            )
        if not resp.get("ok"):
            return None
        return {"status": resp.get("status_code") or 0, "body": resp.get("body") or ""}

    async def _post_reset(self, ctx: ScanContext, url: str, email: str):
        resp = await ctx.tools.http_request(
            method="POST",
            url=url,
            headers={"Content-Type": "application/json"},
            body=f'{{"email":"{email}"}}',
            max_body_bytes=8000,
        )
        if not resp.get("ok"):
            resp = await ctx.tools.http_request(
                method="POST",
                url=url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=f"email={email}&user_login={email}",
                max_body_bytes=8000,
            )
        if not resp.get("ok"):
            return None
        return {"status": resp.get("status_code") or 0, "body": resp.get("body") or ""}


def _normalize(body: str) -> str:
    import re

    # Strip CSRF/tokens/timestamps noise
    t = re.sub(r"[0-9a-f]{8,}", "", (body or "").lower())
    t = re.sub(r"\s+", " ", t)
    return t[:2000]
