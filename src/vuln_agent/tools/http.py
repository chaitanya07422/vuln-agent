from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class HttpRequestTool:
    name = "http_request"

    def __init__(
        self,
        *,
        timeout_sec: float = 15.0,
        user_agent: str = "vuln-agent/0.1",
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

    async def __call__(
        self,
        *,
        method: str = "GET",
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        max_body_bytes: int = 200_000,
    ) -> dict:
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        async with httpx.AsyncClient(
            timeout=self.timeout_sec,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
        ) as client:
            try:
                resp = await client.request(
                    method.upper(),
                    url,
                    headers=req_headers,
                    content=body,
                )
            except httpx.HTTPError as exc:
                return {
                    "ok": False,
                    "error": type(exc).__name__,
                    "detail": str(exc),
                    "url": url,
                    "method": method.upper(),
                }

            text = resp.text
            if len(text.encode("utf-8", errors="ignore")) > max_body_bytes:
                text = text[:max_body_bytes]

            return {
                "ok": True,
                "url": str(resp.url),
                "method": method.upper(),
                "status_code": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()},
                "body": text,
                "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
            }


class ToolBus:
    """Named tools agents call via ctx.tools.<name>(...)."""

    def __init__(self, http: HttpRequestTool) -> None:
        self.http_request = http

    def as_dict(self) -> Dict[str, Any]:
        return {"http_request": self.http_request}
