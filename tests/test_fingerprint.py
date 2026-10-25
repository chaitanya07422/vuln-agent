from vuln_agent.fingerprint import fingerprint


def test_wordpress_tag():
    html = '<html><link rel="https://api.w.org/"/><div class="wp-content">x</div></html>'
    fp = fingerprint({}, html)
    assert "wordpress" in fp["tags"]


def test_unknown_tag():
    fp = fingerprint({"server": "nginx"}, "<html><title>Hi</title></html>")
    assert fp["tags"] == ["unknown"]
    assert fp["title"] == "Hi"
    assert fp["server"] == "nginx"


def test_nextjs_tag():
    fp = fingerprint({}, '<script src="/_next/static/chunks/main.js"></script>')
    assert "nextjs" in fp["tags"]
