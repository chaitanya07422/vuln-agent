from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict


class SmtpBannerTool:
    name = "smtp_banner"

    def __init__(self, timeout_sec: float = 3.0) -> None:
        self.timeout_sec = timeout_sec

    async def __call__(self, *, host: str, port: int = 25) -> Dict[str, Any]:
        def _grab() -> Dict[str, Any]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_sec)
            try:
                sock.connect((host, port))
                data = sock.recv(256)
                banner = data.decode("utf-8", errors="replace").strip()
                # polite close if possible
                try:
                    sock.sendall(b"QUIT\r\n")
                except OSError:
                    pass
                return {"ok": True, "host": host, "port": port, "banner": banner[:200]}
            except OSError as exc:
                return {"ok": False, "host": host, "port": port, "error": str(exc)}
            finally:
                sock.close()

        return await asyncio.to_thread(_grab)
