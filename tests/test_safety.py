from vuln_agent.tools.safety import is_blocked_hostname, is_private_or_local_ip, url_is_safe_target


def test_blocks_localhost():
    assert is_blocked_hostname("localhost")
    assert is_blocked_hostname("foo.local")
    assert is_private_or_local_ip("127.0.0.1")
    assert is_private_or_local_ip("10.0.0.5")
    assert is_private_or_local_ip("192.168.1.1")
    assert not is_private_or_local_ip("1.1.1.1")
    try:
        is_private_or_local_ip("example.com")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_url_safety_example():
    assert url_is_safe_target("https://example.com/", ["example.com"])
    assert not url_is_safe_target("http://127.0.0.1/", ["127.0.0.1"])
    assert not url_is_safe_target("https://evil.com/", ["example.com"])
