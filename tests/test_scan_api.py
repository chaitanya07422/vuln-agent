import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from vuln_agent.main import create_app
from vuln_agent.settings import Settings


@pytest.fixture
def app(tmp_path):
    cfg = tmp_path / "default.yaml"
    cfg.write_text(
        "enabled_agents:\n"
        "  - recon\n"
        "  - leaks\n"
        "  - cors_api\n"
        "  - adapt\n"
        "  - reporter\n"
        "limits:\n  max_rps: 20\n  request_timeout_sec: 20\n  scan_timeout_sec: 120\n"
        "http:\n  user_agent: vuln-agent-test\n  follow_redirects: true\n  max_redirects: 5\n"
    )
    settings = Settings.load(str(cfg))
    return create_app(settings)


@pytest.mark.asyncio
async def test_health(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_attestation_required(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/v1/scans", json={"url": "https://example.com", "attested": False})
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_scan_example_com_e2e(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", timeout=60.0) as client:
        r = await client.post(
            "/v1/scans",
            json={"url": "https://example.com", "attested": True},
        )
        assert r.status_code == 202, r.text
        scan_id = r.json()["id"]

        final = None
        for _ in range(90):
            await asyncio.sleep(0.5)
            g = await client.get(f"/v1/scans/{scan_id}")
            assert g.status_code == 200
            final = g.json()
            if final["status"] in ("done", "failed"):
                break

        assert final is not None
        assert final["status"] == "done", final
        assert "tags" in final["fingerprint"]
        summary = final.get("summary") or {}
        assert summary.get("verdict") in ("looks_solid", "minor_notes", "issues_found")
        assert summary.get("headline")
        assert summary.get("agents")
        # No noisy info cards (recon complete / open ports / report generated)
        for f in final.get("findings") or []:
            assert f["severity"] != "info"
            assert f["agent"] != "reporter"

        report = await client.get(f"/v1/scans/{scan_id}/report.md")
        assert report.status_code == 200
        low = report.text.lower()
        assert "example.com" in low
        assert "security" in low or "each agent" in low or "solid" in low or "finding" in low

        audit = await client.get(f"/v1/scans/{scan_id}/audit.json")
        assert audit.status_code == 200
        assert isinstance(audit.json().get("audit"), list)


@pytest.mark.asyncio
async def test_ui_served(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/")
        assert r.status_code == 200
        assert "vuln-agent" in r.text
