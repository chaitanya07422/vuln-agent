from vuln_agent.agents.cache_poison_hint import response_looks_cacheable
from vuln_agent.agents.cookie_flags import (
    is_bot_or_analytics_cookie,
    is_deletion_cookie,
    parse_cookie,
    split_set_cookie_header,
)
from vuln_agent.agents.redirect_open import EVIL_HOST, _is_external_nav
from vuln_agent.agents.ssrf_hint import _same_response, _strong_accept
from vuln_agent.agents.subdomain_hint import is_wildcard_catch_all
from vuln_agent.agents.xss_reflect_safe import _reflection_context


def test_split_cookies_preserves_expires_comma():
    raw = (
        "nauk_at=; Max-Age=-31536000; Expires=Sun, 26 Oct 2025 19:00:00 GMT, "
        "nauk_rt=; HttpOnly; Max-Age=-1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )
    parts = split_set_cookie_header(raw)
    assert len(parts) == 2
    assert parts[0].startswith("nauk_at=")
    assert parts[1].startswith("nauk_rt=")
    names = [parse_cookie(p)[0] for p in parts if parse_cookie(p)]
    assert names == ["nauk_at", "nauk_rt"]
    assert not any("Oct" in n or "1970" in n or "2025" in n for n in names)


def test_deletion_cookie_detected():
    raw = "nauk_at=; Path=/; Max-Age=-31536000; Expires=Sun, 26 Oct 2025 19:00:00 GMT"
    parsed = parse_cookie(raw)
    assert parsed is not None
    name, value, attrs, is_delete = parsed
    assert name == "nauk_at"
    assert is_delete is True
    assert is_deletion_cookie(f"{name}={value}", attrs) is True


def test_session_cookie_not_delete():
    raw = "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
    parsed = parse_cookie(raw)
    assert parsed is not None
    assert parsed[3] is False


def test_open_redirect_requires_external_location():
    assert _is_external_nav(f"https://{EVIL_HOST}/x", "www.naukri.com") is True
    assert _is_external_nav("/mnjuser/homepage", "www.naukri.com") is False
    assert _is_external_nav("", "www.naukri.com") is False
    # evil only in query of same host is NOT external nav
    assert _is_external_nav(f"https://www.naukri.com/sign-in?next=https://{EVIL_HOST}/", "www.naukri.com") is False


def test_ssrf_ignores_next_html_metadata_boilerplate():
    next_404 = (
        '<!DOCTYPE html><html><head><title>404: This page could not be found.</title>'
        "</head><body><script>self.__next_f=self.__next_f||[]</script>"
        "<meta name='metadata' content='x'/></body></html>"
    )
    assert _strong_accept(next_404, probe="http://127.0.0.1/", code=404) is False
    assert _strong_accept(next_404, probe="http://169.254.169.254/latest/meta-data/", code=404) is False


def test_ssrf_accepts_real_connect_errors():
    body = "Error: connect ECONNREFUSED 127.0.0.1:80"
    assert _strong_accept(body, probe="http://127.0.0.1/", code=500) is True
    meta = "fetch failed: getaddrinfo ENOTFOUND metadata.google.internal"
    assert _strong_accept(meta, probe="http://metadata.google.internal/", code=502) is True


def test_ssrf_baseline_same_response():
    html = "404: This page could not be found. __next_f"
    assert _same_response(404, html, 404, html) is True
    assert _same_response(404, html, 500, "connection refused to 127.0.0.1") is False


def test_wildcard_dns_catch_all():
    shared = {"129.159.226.127"}
    assert is_wildcard_catch_all(shared, shared) is True
    assert is_wildcard_catch_all({"1.2.3.4"}, shared) is False
    assert is_wildcard_catch_all(set(), shared) is False


def test_akamai_bot_cookies_skipped():
    assert is_bot_or_analytics_cookie("_abck") is True
    assert is_bot_or_analytics_cookie("bm_sz") is True
    assert is_bot_or_analytics_cookie("ak_bmsc") is True
    assert is_bot_or_analytics_cookie("session") is False
    assert is_bot_or_analytics_cookie("nauk_at") is False


def test_next_rsc_echo_not_html_xss():
    body = (
        'urlParts":["","profile-performance?q=scanleadXssMarker7f3a"],'
        '"initialTree":["",{"children":["profile-performance"'
    )
    ctx = _reflection_context(body, "scanleadXssMarker7f3a")
    assert ctx["rsc_echo"] is True
    assert ctx["html_context"] is False


def test_html_reflection_still_flagged():
    body = "<div>hello scanleadXssMarker7f3a world</div>"
    ctx = _reflection_context(body, "scanleadXssMarker7f3a")
    assert ctx["html_context"] is True


def test_cache_poison_respects_no_store():
    assert response_looks_cacheable({"cache-control": "max-age=0, no-cache, no-store"}) is False
    assert response_looks_cacheable({"cache-control": "public, max-age=3600"}) is True
    assert response_looks_cacheable({"cache-control": "private, max-age=60"}) is False
