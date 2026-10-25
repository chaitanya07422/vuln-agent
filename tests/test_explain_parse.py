from vuln_agent.agents.explain import parse_explain_lines


def test_parse_pipe_format():
    text = (
        "1|WHY|Auth-gated upload API still proves a real Express upload surface.|FIX|"
        "Keep login; validate MIME server-side; never serve HTML from object URLs.\n"
        "2|WHY|JSON 404 on /objects/uploads/<uuid> means the route exists.|FIX|"
        "Require auth or signed URLs; force Content-Disposition: attachment.\n"
    )
    out = parse_explain_lines(text, 2)
    assert "upload" in out[0][0].lower()
    assert "MIME" in out[0][1] or "mime" in out[0][1].lower()
    assert "route" in out[1][0].lower()
    assert "attachment" in out[1][1].lower()


def test_parse_ignores_bad_index():
    text = "9|WHY|nope|FIX|nope\n1|WHY|good why|FIX|good fix\n"
    out = parse_explain_lines(text, 1)
    assert out[0] == ("good why", "good fix")
