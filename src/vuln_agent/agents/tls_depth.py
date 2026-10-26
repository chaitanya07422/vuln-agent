from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from vuln_agent.agents.base import BaseAgent
from vuln_agent.core.context import ScanContext
from vuln_agent.core.finding import Finding

# Detect-only: cert expiry + basic TLS protocol hygiene via stdlib ssl. No cipher brute.


async def _peer_cert(host: str, port: int = 443) -> Dict[str, Any]:
    def _run() -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(
                __import__("socket").create_connection((host, port), timeout=8),
                server_hostname=host,
            ) as sock:
                cert = sock.getpeercert()
                version = sock.version()
                cipher = sock.cipher()
                return {
                    "ok": True,
                    "cert": cert,
                    "version": version,
                    "cipher": cipher[0] if cipher else None,
                }
        except Exception as exc:
            return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}

    return await asyncio.to_thread(_run)


def _parse_not_after(cert: dict) -> Optional[datetime]:
    # (('notAfter', 'May 15 12:00:00 2027 GMT'), ...)
    na = cert.get("notAfter")
    if not na:
        return None
    try:
        return datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class TlsDepthAgent(BaseAgent):
    name = "tls_depth"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        parsed = urlparse(ctx.url)
        if (parsed.scheme or "").lower() != "https":
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="medium",
                    title="Target URL is not HTTPS",
                    evidence_url=ctx.url,
                    evidence_snippet=parsed.scheme or "missing scheme",
                    fix="Serve the site exclusively over HTTPS with HSTS.",
                    tags=["tls"],
                )
            )
            ctx.fingerprint = dict(ctx.fingerprint or {})
            ctx.fingerprint["tls_depth"] = {"https": False}
            return

        host = parsed.hostname or ctx.scope.host
        port = parsed.port or 443
        info = await _peer_cert(host, port)
        await ctx.audit_event(agent=self.name, tool="tls_peer_cert", result={"ok": info.get("ok"), "version": info.get("version")})

        ctx.fingerprint = dict(ctx.fingerprint or {})
        if not info.get("ok"):
            ctx.fingerprint["tls_depth"] = {"ok": False, "error": info.get("error")}
            # Certificate hostname mismatch / verify failures are useful
            detail = (info.get("detail") or "").lower()
            if any(x in detail for x in ("certificate", "hostname", "verify", "ssl", "tls")):
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="high",
                        title="TLS certificate/handshake problem",
                        evidence_url=ctx.url,
                        evidence_snippet=f"{info.get('error')}: {info.get('detail')}",
                        fix="Install a valid certificate matching the hostname; fix chain and renew before expiry.",
                        tags=["tls", "cert"],
                    )
                )
            return

        cert = info.get("cert") or {}
        not_after = _parse_not_after(cert)
        version = info.get("version") or ""
        ctx.fingerprint["tls_depth"] = {
            "ok": True,
            "version": version,
            "cipher": info.get("cipher"),
            "not_after": not_after.isoformat() if not_after else None,
        }

        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            await ctx.emit_finding(
                Finding(
                    agent=self.name,
                    severity="high",
                    title=f"Obsolete TLS protocol negotiated: {version}",
                    evidence_url=ctx.url,
                    evidence_snippet=version,
                    fix="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
                    tags=["tls", "protocol"],
                )
            )

        if not_after:
            days = (not_after - datetime.now(timezone.utc)).days
            if days < 0:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="critical",
                        title="TLS certificate expired",
                        evidence_url=ctx.url,
                        evidence_snippet=f"notAfter={not_after.isoformat()}",
                        fix="Renew the certificate immediately.",
                        tags=["tls", "cert"],
                    )
                )
            elif days <= 21:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="medium",
                        title=f"TLS certificate expires in {days} day(s)",
                        evidence_url=ctx.url,
                        evidence_snippet=f"notAfter={not_after.isoformat()}",
                        fix="Renew before expiry; automate issuance (ACME).",
                        tags=["tls", "cert"],
                    )
                )

        # Subject CN / SAN presence light check
        subj = cert.get("subject") or ()
        flat = " ".join(str(x) for x in subj)
        if host and flat and host.lower() not in flat.lower():
            # SAN may still match — only info if we can't see SAN easily
            san = cert.get("subjectAltName") or ()
            san_blob = " ".join(str(x) for x in san).lower()
            if host.lower() not in san_blob and not san_blob:
                await ctx.emit_finding(
                    Finding(
                        agent=self.name,
                        severity="low",
                        title="Certificate subject may not clearly include hostname",
                        evidence_url=ctx.url,
                        evidence_snippet=flat[:160],
                        fix="Ensure SANs include all public hostnames.",
                        tags=["tls", "cert"],
                    )
                )
