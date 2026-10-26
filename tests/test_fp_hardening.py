from vuln_agent.agents.cookie_flags import (
    is_deletion_cookie,
    parse_cookie,
    split_set_cookie_header,
)
from vuln_agent.agents.redirect_open import EVIL_HOST, _is_external_nav


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
