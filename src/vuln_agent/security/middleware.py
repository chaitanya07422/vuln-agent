from __future__ import annotations

import time
from ipaddress import ip_address

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class IPGuardMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, security_service) -> None:
        super().__init__(app)
        self.security = security_service

    async def dispatch(self, request: Request, call_next) -> Response:
        started = time.perf_counter()
        # Use the socket peer address. Do NOT trust arbitrary X-Forwarded-For
        # values here; configure Uvicorn's forwarded-header trust for NPM only.
        raw_ip = request.client.host if request.client else ""
        try:
            client_ip = str(ip_address(raw_ip))
        except ValueError:
            client_ip = "unknown"

        if client_ip != "unknown" and await self.security.is_blocked(client_ip):
            await self.security.record({
                "ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "status_code": 403,
                "duration_ms": 0,
                "blocked": True,
            })
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
            )

        try:
            response = await call_next(request)
        except Exception:
            await self.security.record({
                "ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "blocked": False,
            })
            raise

        # Deliberately omit query strings, headers, cookies and request bodies.
        await self.security.record({
            "ip": client_ip,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "blocked": False,
        })
        return response
