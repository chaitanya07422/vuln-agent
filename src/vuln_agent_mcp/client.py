from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx

DEFAULT_API_URL = "https://vulscan.duckdns.org"


class ScanLeadClient:
    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self.api_url = (api_url or os.getenv("SCANLEAD_API_URL") or DEFAULT_API_URL).rstrip("/")
        self.api_key = api_key or os.getenv("SCANLEAD_API_KEY") or ""
        if not self.api_key:
            raise RuntimeError(
                "SCANLEAD_API_KEY is required. Create a Pro API key in ScanLead Settings."
            )
        if not self.api_key.startswith("sl_live_"):
            raise RuntimeError("SCANLEAD_API_KEY must start with sl_live_")
        self._timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "scanlead-mcp/0.1",
        }

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return urljoin(self.api_url + "/", path.lstrip("/"))

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        expect_text: bool = False,
    ) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True) as client:
            res = await client.request(
                method,
                self._url(path),
                headers=self._headers()
                | ({"Content-Type": "application/json"} if json_body is not None else {}),
                json=json_body,
            )
            if res.status_code >= 400:
                detail = res.text
                try:
                    detail = json.dumps(res.json(), indent=2)
                except Exception:
                    pass
                raise RuntimeError(f"HTTP {res.status_code}: {detail[:800]}")
            if expect_text:
                return res.text
            if not res.content:
                return {}
            ctype = res.headers.get("content-type") or ""
            if "application/json" in ctype:
                return res.json()
            return res.text

    async def start_scan(self, url: str, attested: bool) -> Dict[str, Any]:
        if not attested:
            raise RuntimeError(
                "attested must be true — only scan systems you own or are authorized to test."
            )
        return await self.request(
            "POST",
            "/v1/scans",
            json_body={"url": url, "attested": True},
        )

    async def get_scan(self, scan_id: str) -> Dict[str, Any]:
        return await self.request("GET", f"/v1/scans/{scan_id}")

    async def list_scans(self) -> Dict[str, Any]:
        return await self.request("GET", "/v1/scans")

    async def get_brief(self, scan_id: str) -> str:
        return await self.request("GET", f"/v1/scans/{scan_id}/report.md", expect_text=True)

    async def get_quota(self) -> Dict[str, Any]:
        return await self.request("GET", "/v1/scans/quota")

    async def retry_scan(self, scan_id: str) -> Dict[str, Any]:
        return await self.request("POST", f"/v1/scans/{scan_id}/retry")
