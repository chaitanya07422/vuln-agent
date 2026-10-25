import pytest

from vuln_agent.agents.adapt import parse_paths_from_llm
from vuln_agent.llm.base import NullLLM
from vuln_agent.llm.factory import build_llm_router
from vuln_agent.llm.router import LLMRouter


def test_parse_paths_from_llm():
    text = """
    Here are paths:
    - /.env
    /actuator/health
    https://evil.com/x
    /graphql
    note: skip this
    """
    paths = parse_paths_from_llm(text, limit=8)
    assert "/.env" in paths
    assert "/actuator/health" in paths
    assert "/graphql" in paths
    assert all(not p.startswith("http") for p in paths)


@pytest.mark.asyncio
async def test_router_falls_back_when_primary_empty():
    class Boom:
        name = "boom"

        async def complete(self, prompt, *, system=None):
            raise RuntimeError("down")

    class Ok:
        name = "ok"

        async def complete(self, prompt, *, system=None):
            return "hello"

    router = LLMRouter({"adapt": Boom(), "fallback": Ok()})
    assert await router.complete("adapt", "hi") == "hello"


@pytest.mark.asyncio
async def test_factory_without_keys_uses_null(monkeypatch):
    for key in (
        "ANTHROPIC_API_KEY",
        "VULN_AGENT_ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "VULN_AGENT_OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "VULN_AGENT_GEMINI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    router = build_llm_router(
        {"lead": "claude", "adapt": "gemini-flash", "reporter": "openai", "fallback": "openai"}
    )
    # No API keys → null providers
    assert router.provider_name("lead") == "null"
    assert router.provider_name("adapt") == "null"
    assert await router.complete("reporter", "x") == ""


@pytest.mark.asyncio
async def test_null_llm():
    n = NullLLM()
    assert await n.complete("anything") == ""
