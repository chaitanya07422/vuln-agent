from vuln_agent.agents.dedupe import dedupe_findings
from vuln_agent.core.finding import Finding


def test_dedupe_resume_and_upload_chains():
    findings = [
        Finding(
            agent="js_audit",
            severity="high",
            title="resumePath used directly as link href (open URL)",
            tags=["js", "resumePath"],
        ),
        Finding(
            agent="js_audit",
            severity="high",
            title="HR/user 'View Resume' can open attacker-controlled resumePath",
            tags=["js", "resumePath", "phishing"],
        ),
        Finding(
            agent="js_audit",
            severity="high",
            title="Upload presign sends browser file.type to server (client-controlled MIME)",
            tags=["js", "upload", "mime"],
        ),
        Finding(
            agent="js_audit",
            severity="high",
            title="Upload pipeline likely allows unsafe types + public object URLs",
            tags=["js", "upload", "chain"],
        ),
        Finding(
            agent="js_audit",
            severity="medium",
            title="Upload accept= is client-side only (easy to bypass)",
            tags=["js", "upload"],
        ),
        Finding(
            agent="adapt",
            severity="medium",
            title="Protected API responds: GET /api/profile",
            tags=["adapt", "probe"],
        ),
        Finding(
            agent="adapt",
            severity="medium",
            title="Protected API responds: GET /api/auth/user",
            tags=["adapt", "probe"],
        ),
    ]
    out = dedupe_findings(findings)
    titles = [f.title for f in out]
    assert len([t for t in titles if "resume" in t.lower()]) == 1
    assert len([t for t in titles if "upload" in t.lower() or "mime" in t.lower() or "accept" in t.lower()]) == 1
    assert any("Protected APIs respond" in t for t in titles)
    assert not any(t.startswith("Protected API responds:") for t in titles)
