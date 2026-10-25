from vuln_agent.agents.upload import _auth_gated_json, _is_json_api_body, _is_upload_path

WP_404 = """<!doctype html>
<html lang="en-US">
<head><title>Page not found</title></head>
<body><a href="/wp-login.php">Log in</a></body>
</html>
"""


def test_wordpress_html_404_not_json_api():
    headers = {"content-type": "text/html; charset=UTF-8"}
    assert not _is_json_api_body(WP_404, headers)
    assert not _auth_gated_json(404, WP_404, headers)
    assert not _auth_gated_json(401, WP_404, headers)


def test_real_json_401_counts():
    body = '{"error":"Please log in to upload files."}'
    headers = {"content-type": "application/json"}
    assert _is_json_api_body(body, headers)
    assert _auth_gated_json(401, body, headers)


def test_upload_path_not_confused_with_profile():
    assert not _is_upload_path("/api/profile")
    assert not _is_upload_path("/api/auth/user")
    assert _is_upload_path("/api/uploads/request-url")
    assert _is_upload_path("/api/files/presign")
    assert _is_upload_path("/upload")

