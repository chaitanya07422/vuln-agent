from vuln_agent.agents.content_guards import (
    looks_like_dotenv,
    looks_like_git_head,
    looks_like_html_document,
    reject_spa_shell_for_leak,
)

SPA = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Netopsys AI Pvt Ltd - AI Solutions & Software Development</title>
  </head>
  <body><div id="root"></div></body>
</html>
"""


def test_spa_html_detected():
    assert looks_like_html_document(SPA, {"content-type": "text/html; charset=UTF-8"})
    assert reject_spa_shell_for_leak(SPA, {"content-type": "text/html"}, "/.env")
    assert reject_spa_shell_for_leak(SPA, {"content-type": "text/html"}, "/backup.zip")
    assert reject_spa_shell_for_leak(SPA, {"content-type": "text/html"}, "/api/upload")


def test_real_dotenv_accepted():
    env = "DATABASE_URL=postgres://x\nAPI_KEY=secret123\n"
    assert looks_like_dotenv(env)
    assert not looks_like_dotenv(SPA)


def test_git_head():
    assert looks_like_git_head("ref: refs/heads/main\n")
    assert not looks_like_git_head(SPA)
