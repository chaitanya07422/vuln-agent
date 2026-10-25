from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List


DEFAULT_PORTS = [21, 22, 25, 80, 443, 445, 3306, 5432, 6379, 8080, 8443, 27017]


class PortProbeTool:
    name = "port_probe"

    def __init__(self, timeout_sec: float = 2.0) -> None:
        self.timeout_sec = timeout_sec

    async def __call__(
        self,
        *,
        host: str,
        ports: List[int] | None = None,
    ) -> Dict[str, Any]:
        ports = ports or DEFAULT_PORTS

        async def _one(port: int) -> Dict[str, Any]:
            def _connect() -> bool:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout_sec)
                try:
                    sock.connect((host, port))
                    return True
                except OSError:
                    return False
                finally:
                    sock.close()

            open_ = await asyncio.to_thread(_connect)
            return {"port": port, "open": open_}

        results = await asyncio.gather(*[_one(p) for p in ports])
        open_ports = [r["port"] for r in results if r["open"]]
        return {"ok": True, "host": host, "open_ports": open_ports, "results": list(results)}
