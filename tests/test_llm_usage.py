from vuln_agent.llm.usage import LLMCallUsage, estimate_tokens, summarize_usage


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 8) == 2


def test_summarize_usage():
    calls = [
        LLMCallUsage(provider="gemini", model="gemini-flash-latest", role="adapt", total_tokens=100),
        LLMCallUsage(provider="gemini", model="gemini-flash-latest", role="reporter", total_tokens=50),
    ]
    s = summarize_usage(calls)
    assert s["call_count"] == 2
    assert s["total_tokens"] == 150
    assert s["by_role"]["adapt"]["total_tokens"] == 100
    assert s["by_model"]["gemini-flash-latest"]["calls"] == 2
