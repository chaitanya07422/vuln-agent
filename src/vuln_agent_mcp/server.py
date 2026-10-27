from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Dict, List, Optional

from vuln_agent_mcp.client import ScanLeadClient

SERVER_NAME = "scanlead"
SERVER_VERSION = "0.1.0"

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "start_scan",
        "description": (
            "Start an authorized ScanLead detect-only scan. "
            "Requires attested=true (you own or are authorized to test the URL)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL including https://"},
                "attested": {
                    "type": "boolean",
                    "description": "Must be true — ownership/authorization attestation",
                },
            },
            "required": ["url", "attested"],
        },
    },
    {
        "name": "get_scan",
        "description": "Get scan status, progress, summary, and findings (respects freemium reveal).",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_scans",
        "description": "List scans saved to the authenticated ScanLead account.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_brief",
        "description": "Fetch the markdown company brief for a scan.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "get_quota",
        "description": (
            "Show remaining scan quota for the API key owner. "
            "Free: MCP is a separate 1-scan bucket from web. "
            "Pro: web and MCP share one quota pool."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "retry_scan",
        "description": "Retry a failed scan without consuming a new quota slot.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
]


def _ok_text(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def _ok_json(data: Any) -> Dict[str, Any]:
    return _ok_text(json.dumps(data, indent=2, default=str))


class McpStdioServer:
    def __init__(self) -> None:
        self._client: Optional[ScanLeadClient] = None

    def client(self) -> ScanLeadClient:
        if self._client is None:
            self._client = ScanLeadClient()
        return self._client

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        c = self.client()
        try:
            if name == "start_scan":
                data = await c.start_scan(
                    str(arguments.get("url") or ""),
                    bool(arguments.get("attested")),
                )
                return _ok_json(data)
            if name == "get_scan":
                return _ok_json(await c.get_scan(str(arguments.get("scan_id") or "")))
            if name == "list_scans":
                return _ok_json(await c.list_scans())
            if name == "get_brief":
                md = await c.get_brief(str(arguments.get("scan_id") or ""))
                return _ok_text(md if isinstance(md, str) else str(md))
            if name == "get_quota":
                return _ok_json(await c.get_quota())
            if name == "retry_scan":
                return _ok_json(await c.retry_scan(str(arguments.get("scan_id") or "")))
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }

    def handle_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Sync dispatch for initialize/tools/list; tools/call runs async separately."""
        method = msg.get("method")
        msg_id = msg.get("id")
        # Notifications have no id — ignore after initialized
        if msg_id is None and method and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}
        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}
        return None


async def _process_tools_call(server: McpStdioServer, msg: Dict[str, Any]) -> Dict[str, Any]:
    msg_id = msg.get("id")
    params = msg.get("params") or {}
    name = params.get("name") or ""
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}
    result = await server.call_tool(name, arguments)
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _write(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


async def run_stdio() -> None:
    server = McpStdioServer()
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        method = msg.get("method")
        if method == "tools/call":
            _write(await _process_tools_call(server, msg))
            continue
        resp = server.handle_message(msg)
        if resp is not None:
            _write(resp)
        elif msg.get("id") is not None:
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )


def main() -> None:
    try:
        asyncio.run(run_stdio())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
