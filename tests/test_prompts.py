from vuln_agent.agents.explain import build_explain_prompt
from vuln_agent.core.context import ScanContext, Scope
from vuln_agent.core.finding import Finding
from vuln_agent.llm.prompts import (
    ADAPT_SYSTEM,
    EXPLAIN_SYSTEM,
    JS_AUDIT_SYSTEM,
    REPORTER_SYSTEM,
    RISK_PATH_SYSTEM,
    format_adapt_user,
    format_js_audit_user,
    format_reporter_user,
    format_risk_path_user,
)


def test_prompt_constants_are_substantial():
    for name, text in [
        ("EXPLAIN", EXPLAIN_SYSTEM),
        ("RISK", RISK_PATH_SYSTEM),
        ("ADAPT", ADAPT_SYSTEM),
        ("JS", JS_AUDIT_SYSTEM),
        ("REPORT", REPORTER_SYSTEM),
    ]:
        assert "ScanLead" in text, name
        assert len(text) > 200, name


def test_format_helpers_and_explain_prompt():
    risk = format_risk_path_user(
        url="https://example.com",
        fingerprint={"tags": ["spa"]},
        bullets=["- [high] (upload) unsafe upload"],
    )
    assert "example.com" in risk
    assert "unsafe upload" in risk

    adapt = format_adapt_user(
        url="https://example.com",
        tags=["spa"],
        fingerprint_detail={"server": "nginx"},
        js_paths=["/api/uploads/request-url"],
    )
    assert "/api/uploads/request-url" in adapt

    js = format_js_audit_user(
        url="https://example.com",
        fingerprint={},
        api_paths=["/api/x"],
        excerpts=["resumePath", "contentType"],
    )
    assert "resumePath" in js

    report = format_reporter_user(brief="# Security brief\n")
    assert report.startswith("Polish")
    assert "# Security brief" in report

    ctx = ScanContext(
        scan_id="t",
        url="https://example.com",
        scope=Scope.from_url("https://example.com"),
        tools=None,
        fingerprint={"tags": ["spa"]},
    )
    ctx.findings = [
        Finding(
            agent="upload",
            severity="high",
            title="Open upload",
            evidence_snippet="HTTP 200",
            fix="lock MIME",
            tags=["upload"],
        )
    ]
    prompt = build_explain_prompt(ctx, ctx.findings)
    assert "N|WHY|" in prompt or "WHY" in prompt
    assert "Open upload" in prompt
    assert "example.com" in prompt
