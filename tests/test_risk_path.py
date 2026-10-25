from vuln_agent.agents.risk_path import _clean_path, heuristic_risk_path
from vuln_agent.core.context import ScanContext, Scope
from vuln_agent.core.finding import Finding


def test_heuristic_upload_resume_chain():
    ctx = ScanContext(
        scan_id="t",
        url="https://example.com",
        scope=Scope(host="example.com", scheme="https", allow_hosts=["example.com"]),
        tools=None,
    )
    ctx.findings = [
        Finding(
            agent="upload",
            severity="medium",
            title="Upload/presign API present (auth required): /api/uploads/request-url",
            tags=["upload", "presign"],
        ),
        Finding(
            agent="js_audit",
            severity="high",
            title="resumePath used directly as link href (open URL)",
            tags=["js", "resumePath"],
        ),
    ]
    text = heuristic_risk_path(ctx)
    assert "upload" in text.lower()
    assert "resume" in text.lower() or "link" in text.lower()
    assert "Priority fix" in text
    assert "curl" not in text.lower()
    assert "payload" not in text.lower()


def test_clean_strips_fences():
    raw = "```\n1. Step one\n2. Step two\n```\nPriority fix: lock uploads."
    assert "```" not in _clean_path(raw)
    assert "Step one" in _clean_path(raw)
