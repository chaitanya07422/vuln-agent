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
    ctx.fingerprint = {"tags": ["express"]}
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
    assert text.count("Defenders should treat") <= 1


def test_heuristic_follows_findings_not_stack_guesses():
    """Any future URL: story must come from findings, not invent upload on CMS sites."""
    ctx = ScanContext(
        scan_id="t",
        url="https://www.doctutorials.com/",
        scope=Scope(host="www.doctutorials.com", scheme="https", allow_hosts=["www.doctutorials.com"]),
        tools=None,
    )
    ctx.fingerprint = {"tags": ["wordpress"]}
    ctx.findings = [
        Finding(
            agent="users",
            severity="high",
            title="Public WordPress user enumeration",
            tags=["wordpress", "users"],
        ),
        Finding(
            agent="auth",
            severity="high",
            title="WordPress XML-RPC enabled",
            tags=["wordpress", "xmlrpc"],
        ),
    ]
    text = heuristic_risk_path(ctx)
    assert "upload" not in text.lower()
    assert "author" in text.lower() or "account" in text.lower()
    assert "remote" in text.lower() or "login" in text.lower()
    assert "Priority fix" in text
    assert text.count("Defenders should treat") == 0


def test_clean_strips_fences():
    raw = "```\n1. Step one\n2. Step two\n```\nPriority fix: lock uploads."
    assert "```" not in _clean_path(raw)
    assert "Step one" in _clean_path(raw)
