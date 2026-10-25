import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from vuln_agent.main import create_app
from vuln_agent.settings import Settings


@pytest.fixture
def app(tmp_path, monkeypatch):
    cfg = tmp_path / "default.yaml"
    cfg.write_text(
        "enabled_agents:\n  - recon\n"
        "limits:\n  request_timeout_sec: 20\n  scan_timeout_sec: 60\n"
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
    """Live network E2E: create scan → wait → report with recon findings."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/v1/scans",
            json={"url": "https://example.com", "attested": True},
        )
        assert r.status_code == 202, r.text
        scan_id = r.json()["id"]

        final = None
        for _ in range(40):
            await asyncio.sleep(0.25)
            g = await client.get(f"/v1/scans/{scan_id}")
            assert g.status_code == 200
            final = g.json()
            if final["status"] in ("done", "failed"):
                break

        assert final is not None
        assert final["status"] == "done", final
        assert final["findings"], "expected recon findings"
        assert any(f["agent"] == "recon" for f in final["findings"])
        assert "tags" in final["fingerprint"]

        report = await client.get(f"/v1/scans/{scan_id}/report.md")
        assert report.status_code == 200
        assert "Scan report" in report.text
        assert "example.com" in report.text
