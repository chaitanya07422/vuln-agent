from __future__ import annotations

import os
from typing import Optional

import httpx

from vuln_agent.llm.base import NullLLM


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": self.model, "messages": messages, "temperature": 0.2},
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()


class ClaudeProvider:
    name = "claude"

    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-latest") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        async with httpx.AsyncClient(timeout=45.0) as client:
            payload = {
                "model": self.model,
                "max_tokens": 1200,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                payload["system"] = system
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            parts = data.get("content") or []
            texts = [p.get("text", "") for p in parts if p.get("type") == "text"]
            return "\n".join(texts).strip()


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        text = f"{system}\n\n{prompt}" if system else prompt
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                url,
                headers={"content-type": "application/json"},
                json={"contents": [{"parts": [{"text": text}]}]},
            )
            resp.raise_for_status()
            data = resp.json()
            candidates = data.get("candidates") or []
            if not candidates:
                return ""
            parts = candidates[0].get("content", {}).get("parts") or []
            return "".join(p.get("text", "") for p in parts).strip()


def build_provider(name: Optional[str]):
    """Map config name → provider. Missing keys → NullLLM (scans still work)."""
    if not name or name in ("null", "none", "off"):
        return NullLLM()

    key = name.strip().lower()
    if key in ("claude", "anthropic"):
        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("VULN_AGENT_ANTHROPIC_API_KEY")
        if not api_key:
            return NullLLM()
        model = os.getenv("VULN_AGENT_CLAUDE_MODEL", "claude-3-5-haiku-latest")
        return ClaudeProvider(api_key, model=model)

    if key in ("openai", "gpt"):
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("VULN_AGENT_OPENAI_API_KEY")
        if not api_key:
            return NullLLM()
        model = os.getenv("VULN_AGENT_OPENAI_MODEL", "gpt-4o-mini")
        return OpenAIProvider(api_key, model=model)

    if key in ("gemini", "gemini-flash", "google"):
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv(
            "VULN_AGENT_GEMINI_API_KEY"
        )
        if not api_key:
            return NullLLM()
        model = os.getenv("VULN_AGENT_GEMINI_MODEL", "gemini-2.0-flash")
        return GeminiProvider(api_key, model=model)

    return NullLLM()
