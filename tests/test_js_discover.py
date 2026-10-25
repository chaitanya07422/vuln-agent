from vuln_agent.agents.js_discover import extract_api_paths, script_urls
from vuln_agent.agents.upload import _homepage_sig, _is_spa_shell


def test_extract_api_paths():
    js = 'fetch("/api/uploads/request-url",{method:"POST"}); fetch("/api/jobs")'
    paths = extract_api_paths(js)
    assert "/api/uploads/request-url" in paths
    assert "/api/jobs" in paths


def test_script_urls():
    html = '<script src="/assets/index-abc.js"></script>'
    urls = script_urls(html, "https://example.com/")
    assert urls == ["https://example.com/assets/index-abc.js"]


def test_spa_shell_vs_other_html():
    home = "<!doctype html><html><head><title>Home</title></head><body><div id='root'></div></body></html>"
    other = "<!doctype html><html><head><title>Phish</title></head><body><h1>Login</h1></body></html>"
    hs = _homepage_sig(home, {"content-type": "text/html"})
    assert _is_spa_shell(home, {"content-type": "text/html"}, hs)
    assert not _is_spa_shell(other, {"content-type": "text/html"}, hs)
