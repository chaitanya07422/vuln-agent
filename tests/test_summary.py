from vuln_agent.agents.summary import build_scan_summary, strip_noise_findings
from vuln_agent.core.context import ScanContext, Scope
from vuln_agent.core.finding import Finding


def _ctx(findings):
    ctx = ScanContext(
        scan_id="t",
        url="https://example.com",
        scope=Scope(host="example.com", scheme="https", allow_hosts=["example.com"]),
        tools=None,
    )
    ctx.fingerprint = {"tags": ["express"]}
    ctx.findings = findings
    return ctx


def test_strip_noise():
    findings = [
        Finding(agent="recon", severity="info", title="Recon complete — HTTP 200"),
        Finding(agent="ports_mail", severity="info", title="Open ports: [80, 443]"),
        Finding(agent="users", severity="high", title="Public WordPress user enumeration"),
        Finding(agent="reporter", severity="info", title="Report generated"),
    ]
    out = strip_noise_findings(findings)
    assert len(out) == 1
    assert out[0].agent == "users"


def test_looks_solid_only_when_empty():
    ctx = _ctx([])
    s = build_scan_summary(ctx, enabled_agents=["recon", "upload", "leaks"])
    assert s["all_clear"] is True
    assert s["verdict"] == "looks_solid"
    assert "solid" in s["headline"].lower()


def test_never_solid_with_high():
    ctx = _ctx(
        [
            Finding(
                agent="auth",
                severity="high",
                title="WordPress XML-RPC enabled",
                tags=["xmlrpc"],
            )
        ]
    )
    s = build_scan_summary(ctx, enabled_agents=["auth", "upload"])
    assert s["all_clear"] is False
    assert s["verdict"] == "issues_found"
    assert "perfect" not in s["headline"].lower()
    assert any(r["status"] == "attention" for r in s["agents"] if r["agent"] == "auth")
    assert any(r["status"] == "clear" for r in s["agents"] if r["agent"] == "upload")
