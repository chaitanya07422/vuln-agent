from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List


class DnsLookupTool:
    name = "dns_lookup"

    async def __call__(self, *, host: str) -> Dict[str, Any]:
        def _resolve() -> Dict[str, Any]:
            try:
                infos = socket.getaddrinfo(host, None)
                addrs = sorted({i[4][0] for i in infos})
                return {"ok": True, "host": host, "addresses": addrs}
            except socket.gaierror as exc:
                return {"ok": False, "host": host, "error": str(exc), "addresses": []}

        return await asyncio.to_thread(_resolve)


class MxLookupTool:
    name = "mx_lookup"

    async def __call__(self, *, host: str) -> Dict[str, Any]:
        # Lightweight: try common mail hostnames; full DNS MX needs dnspython (optional later)
        candidates = [f"mail.{host}", f"smtp.{host}", host]
        found: List[str] = []
        dns = DnsLookupTool()
        for c in candidates:
            res = await dns(host=c)
            if res.get("ok") and res.get("addresses"):
                found.append(c)
        return {"ok": True, "host": host, "mail_hosts": found}
