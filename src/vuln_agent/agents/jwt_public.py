from __future__ import annotations

import json
from urllib.parse import urljoin

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: JWKS / OIDC discovery; alg / key exposure hints. No forging or signing.

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
]
JWKS_PATHS = ["/.well-known/jwks.json", "/jwks.json", "/oauth/jwks", "/.well-known/jwks"]


class JwtPublicAgent(BaseAgent):
    name = "jwt_public"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
        discovery = None
        jwks_uri = None

        for path in OIDC_PATHS:
            target = urljoin(base, path.lstrip("/"))
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=50_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
                continue
            try:
                data = json.loads(resp.get("body") or "")
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and (data.get("jwks_uri") or data.get("issuer")):
                discovery = data
                jwks_uri = data.get("jwks_uri")
                break

        jwks = None
        targets = ([jwks_uri] if jwks_uri else []) + [urljoin(base, p.lstrip("/")) for p in JWKS_PATHS]
        for target in targets[:5]:
            if not target:
                continue
            resp = await ctx.tools.http_request(method="GET", url=target, max_body_bytes=50_000)
            await ctx.audit_event(agent=self.name, tool="http_request", url=target, ok=resp.get("ok"))
            if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
                continue
            try:
                data = json.loads(resp.get("body") or "")
            except json.JSONDecodeError:
                continue
            keys = data.get("keys") if isinstance(data, dict) else None
            if isinstance(keys, list):
                jwks = data
                jwks_uri = target
                break

        ctx.fingerprint = dict(ctx.fingerprint or {})
        ctx.fingerprint["jwt_public"] = {
            "oidc": bool(discovery),
            "jwks": bool(jwks),
            "jwks_uri": jwks_uri,
        }

        if discovery:
            algs = discovery.get("id_token_signing_alg_values_supported") or []
            if "none" in [str(a).lower() for a in algs]:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high",
                        title="OIDC discovery advertises 'none' signing alg",
                        evidence_url=ctx.url,
                        evidence_snippet=str(algs)[:200],
                        fix="Remove none from supported algs; require asymmetric signing.",
                        tags=["jwt", "oidc"],
                    )
                )

        if jwks and isinstance(jwks.get("keys"), list):
            for key in jwks["keys"][:8]:
                kty = str(key.get("kty") or "")
                # Symmetric key material in JWKS is a serious misconfig
                if kty.upper() == "oct" or key.get("k"):
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="critical",
                            title="JWKS exposes symmetric key material",
                            evidence_url=jwks_uri or ctx.url,
                            evidence_snippet=f"kty={kty}",
                            fix="Never publish private/symmetric keys in JWKS; publish only public keys.",
                            tags=["jwt", "jwks"],
                        )
                    )
                if key.get("d") or key.get("p") or key.get("q") or key.get("private"):
                    await ctx.emit_finding(
                        Finding(
                            agent=self.name,
                            severity="critical",
                            title="JWKS appears to include private key parameters",
                            evidence_url=jwks_uri or ctx.url,
                            evidence_snippet="private-looking JWK fields present",
                            fix="Publish only public JWKs (n/e or x/y); rotate compromised keys.",
                            tags=["jwt", "jwks"],
                        )
                    )
