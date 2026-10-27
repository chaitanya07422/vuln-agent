import json

import pytest

from vuln_agent_mcp.server import McpStdioServer, TOOLS, _process_tools_call


def test_initialize_handshake():
    server = McpStdioServer()
    resp = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }
    )
    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "scanlead"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_list():
    server = McpStdioServer()
    resp = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert resp is not None
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {t["name"] for t in TOOLS}
    assert "start_scan" in names
    assert "get_brief" in names
    assert "retry_scan" in names


def test_notifications_have_no_response():
    server = McpStdioServer()
    assert server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


@pytest.mark.asyncio
async def test_start_scan_requires_attestation(monkeypatch):
    from vuln_agent_mcp.client import ScanLeadClient

    server = McpStdioServer()
    # Real client validation; never hits the network when attested is false.
    monkeypatch.setattr(
        server,
        "client",
        lambda: ScanLeadClient(api_url="http://127.0.0.1:9", api_key="sl_live_test"),
    )
    result = await server.call_tool("start_scan", {"url": "https://example.com", "attested": False})
    assert result.get("isError") is True
    assert "attested" in result["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_tools_call_get_quota(monkeypatch):
    server = McpStdioServer()

    class Fake:
        async def get_quota(self):
            return {"plan": "pro", "remaining": 5}

    monkeypatch.setattr(server, "client", lambda: Fake())
    resp = await _process_tools_call(
        server,
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "get_quota", "arguments": {}}},
    )
    assert resp["id"] == 9
    body = json.loads(resp["result"]["content"][0]["text"])
    assert body["remaining"] == 5
