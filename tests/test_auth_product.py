from vuln_agent.core.scan_diff import diff_findings
from vuln_agent.core.html_report import render_scan_html
from vuln_agent.auth.tokens import create_access_token, decode_token, public_user


def test_diff_findings_new_fixed_still():
    prev = [
        {"agent": "leaks", "severity": "high", "title": "Open .git"},
        {"agent": "cors_api", "severity": "medium", "title": "CORS *"},
    ]
    curr = [
        {"agent": "cors_api", "severity": "medium", "title": "CORS *"},
        {"agent": "auth", "severity": "high", "title": "User enum"},
    ]
    d = diff_findings(prev, curr)
    assert d["counts"]["new"] == 1
    assert d["counts"]["fixed"] == 1
    assert d["counts"]["still_open"] == 1
    assert d["new"][0]["title"] == "User enum"
    assert d["fixed"][0]["title"] == "Open .git"


def test_html_report_watermark():
    scan = {
        "url": "https://example.com",
        "status": "done",
        "summary": {"headline": "Looks solid", "verdict": "looks_solid", "agents": []},
        "findings": [],
    }
    free = render_scan_html(scan, branded=False)
    pro = render_scan_html(scan, branded=True)
    assert "upgrade for branded" in free.lower()
    assert "upgrade for branded" not in pro.lower()


def test_access_token_roundtrip():
    user = {"id": "u1", "email": "a@b.com", "name": "A", "plan": "free"}
    token = create_access_token(user)
    payload = decode_token(token, expect_typ="access")
    assert payload["sub"] == "u1"
    assert public_user(user)["email"] == "a@b.com"
