from vuln_agent.agents.input_hygiene import _form_targets, _leaky


def test_leaky_detects_traceback():
    assert _leaky("Traceback (most recent call last):\n  File", 500) == "traceback"


def test_leaky_ignores_clean_json():
    assert _leaky('{"ok":true}', 200) is None


def test_form_targets_extracts_fields():
    html = """
    <form action="/contact" method="post">
      <input type="email" name="email" required />
      <input type="text" name="message" maxlength="100" />
      <button type="submit">Send</button>
    </form>
    """
    targets = _form_targets(html, "https://example.com/")
    assert targets
    assert targets[0]["method"] == "POST"
    names = {f["name"] for f in targets[0]["fields"]}
    assert "email" in names
    assert "message" in names
    assert "email" in targets[0]["client_hints"]
