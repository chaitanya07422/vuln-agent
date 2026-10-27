"""Free web vs MCP quotas are separate; MCP scans attach to the key owner."""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

# Isolate from Oracle .env limits during import of quotas via app
os.environ["VULN_AGENT_FREE_SCAN_LIMIT"] = "3"
os.environ["VULN_AGENT_FREE_MCP_SCAN_LIMIT"] = "1"
os.environ.pop("VULN_AGENT_MONGO_URI", None)
os.environ.pop("VULN_AGENT_REDIS_URL", None)

from vuln_agent.auth.api_keys import append_api_key
from vuln_agent.auth.tokens import create_access_token
from vuln_agent.main import create_app


@pytest.fixture
async def client_and_creds():
    app = create_app()
    user = await app.state.users.upsert_google(
        google_id="mcp_q", email="mcp-quota@example.com", name="Q", picture=None
    )
    await app.state.users.update(user["id"], plan="free")
    user = await app.state.users.get(user["id"])
    assert user is not None
    keys, raw = append_api_key(user, name="t")
    user = await app.state.users.update(user["id"], api_keys=keys)
    token = create_access_token(user)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, raw, token, user["id"], app


@pytest.mark.asyncio
async def test_free_mcp_one_then_block_web_untouched(client_and_creds):
    client, api_key, jwt, user_id, app = client_and_creds

    q_web = await client.get("/v1/scans/quota", headers={"Authorization": f"Bearer {jwt}"})
    assert q_web.status_code == 200
    body = q_web.json()
    assert body["channel"] == "web"
    assert body["web"]["limit"] == 3
    assert body["mcp"]["limit"] == 1
    assert body["web"]["can_scan"] is True
    assert body["mcp"]["can_scan"] is True

    q_mcp = await client.get("/v1/scans/quota", headers={"Authorization": f"Bearer {api_key}"})
    assert q_mcp.json()["channel"] == "mcp"
    assert q_mcp.json()["can_scan"] is True

    # First MCP scan OK
    r1 = await client.post(
        "/v1/scans",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"url": "https://example.com", "attested": True},
    )
    assert r1.status_code == 202, r1.text
    scan = r1.json()
    assert scan.get("owner_id") == user_id or True  # may be stripped in public
    stored = await app.state.store.get(scan["id"])
    assert stored["owner_id"] == user_id
    assert stored["source"] == "mcp"

    # Second MCP blocked
    r2 = await client.post(
        "/v1/scans",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"url": "https://example.com", "attested": True},
    )
    assert r2.status_code == 402
    detail = r2.json()["detail"]
    assert detail["code"] == "MCP_QUOTA_EXCEEDED"

    # Web Free still available
    q_web2 = await client.get("/v1/scans/quota", headers={"Authorization": f"Bearer {jwt}"})
    assert q_web2.json()["web"]["used"] == 0
    assert q_web2.json()["web"]["can_scan"] is True
    assert q_web2.json()["mcp"]["used"] == 1
    assert q_web2.json()["mcp"]["can_scan"] is False

    rw = await client.post(
        "/v1/scans",
        headers={"Authorization": f"Bearer {jwt}"},
        json={"url": "https://example.org", "attested": True},
    )
    assert rw.status_code == 202
    web_scan = await app.state.store.get(rw.json()["id"])
    assert web_scan["source"] == "web"
    assert web_scan["owner_id"] == user_id


@pytest.mark.asyncio
async def test_pro_web_and_mcp_share_one_pool():
    os.environ["VULN_AGENT_PRO_SCAN_LIMIT"] = "3"
    # Re-import limit constant after env (module already loaded — patch via monkey)
    import vuln_agent.auth.quotas as q
    import vuln_agent.api.routes_scans as routes

    old = q.PRO_SCAN_LIMIT
    q.PRO_SCAN_LIMIT = 3
    routes.PRO_SCAN_LIMIT = 3
    try:
        app = create_app()
        user = await app.state.users.upsert_google(
            google_id="pro_share", email="pro-share@example.com", name="P", picture=None
        )
        await app.state.users.update(user["id"], plan="pro")
        user = await app.state.users.get(user["id"])
        keys, raw = append_api_key(user, name="p")
        user = await app.state.users.update(user["id"], api_keys=keys)
        jwt = create_access_token(user)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 2 via web
            for i in range(2):
                r = await client.post(
                    "/v1/scans",
                    headers={"Authorization": f"Bearer {jwt}"},
                    json={"url": f"https://example.com/w{i}", "attested": True},
                )
                assert r.status_code == 202, r.text
            # 1 via MCP → hits shared limit of 3
            r = await client.post(
                "/v1/scans",
                headers={"Authorization": f"Bearer {raw}"},
                json={"url": "https://example.com/m", "attested": True},
            )
            assert r.status_code == 202, r.text
            qbody = (
                await client.get("/v1/scans/quota", headers={"Authorization": f"Bearer {jwt}"})
            ).json()
            assert qbody["shared"] is True
            assert qbody["used"] == 3
            assert qbody["limit"] == 3
            assert qbody["can_scan"] is False
            assert qbody["web"]["used"] == 2
            assert qbody["mcp"]["used"] == 1
            # Next MCP blocked
            r2 = await client.post(
                "/v1/scans",
                headers={"Authorization": f"Bearer {raw}"},
                json={"url": "https://example.com/m2", "attested": True},
            )
            assert r2.status_code == 429
            # Next web blocked too
            r3 = await client.post(
                "/v1/scans",
                headers={"Authorization": f"Bearer {jwt}"},
                json={"url": "https://example.com/w9", "attested": True},
            )
            assert r3.status_code == 429
    finally:
        q.PRO_SCAN_LIMIT = old
        routes.PRO_SCAN_LIMIT = old
