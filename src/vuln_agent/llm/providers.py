from __future__ import annotations

import os
from typing import Optional

import httpx

from vuln_agent.llm.base import NullLLM
from vuln_agent.llm.usage import LLMCallUsage, estimate_tokens


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        self.api_key = api_key
        self.model = model
        self.last_usage: Optional[LLMCallUsage] = None

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
            text = data["choices"][0]["message"]["content"].strip()
            usage = data.get("usage") or {}
            pt = int(usage.get("prompt_tokens") or 0)
            ct = int(usage.get("completion_tokens") or 0)
            if not pt and not ct:
                pt = estimate_tokens((system or "") + prompt)
                ct = estimate_tokens(text)
            self.last_usage = LLMCallUsage(
                provider=self.name,
                model=self.model,
                prompt_tokens=pt,
                completion_tokens=ct,
                total_tokens=int(usage.get("total_tokens") or (pt + ct)),
                ok=True,
            )
            return text


class ClaudeProvider:
    name = "claude"

    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-latest") -> None:
        self.api_key = api_key
        self.model = model
        self.last_usage: Optional[LLMCallUsage] = None

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
            text = "\n".join(texts).strip()
            usage = data.get("usage") or {}
            pt = int(usage.get("input_tokens") or 0)
            ct = int(usage.get("output_tokens") or 0)
            if not pt and not ct:
                pt = estimate_tokens((system or "") + prompt)
                ct = estimate_tokens(text)
            self.last_usage = LLMCallUsage(
                provider=self.name,
                model=self.model,
                prompt_tokens=pt,
                completion_tokens=ct,
                total_tokens=pt + ct,
                ok=True,
            )
            return text


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-flash-latest") -> None:
        self.api_key = api_key
        self.model = model
        self.last_usage: Optional[LLMCallUsage] = None

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        text = f"{system}\n\n{prompt}" if system else prompt
        # Prefer configured model, then current Flash aliases
        models = [self.model]
        for alt in ("gemini-flash-latest", "gemini-2.5-flash", "gemini-2.0-flash"):
            if alt not in models:
                models.append(alt)

        last_err: Optional[Exception] = None
        async with httpx.AsyncClient(timeout=45.0) as client:
            for model in models:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{model}:generateContent?key={self.api_key}"
                )
                try:
                    resp = await client.post(
                        url,
                        headers={"content-type": "application/json"},
                        json={"contents": [{"parts": [{"text": text}]}]},
                    )
                    if resp.status_code == 404:
                        continue
                    if resp.status_code >= 400:
                        last_err = RuntimeError(f"Gemini {model} HTTP {resp.status_code}: {resp.text[:200]}")
                        self.last_usage = LLMCallUsage(
                            provider=self.name,
                            model=model,
                            ok=False,
                            error=f"HTTP {resp.status_code}",
                        )
                        continue
                    data = resp.json()
                    candidates = data.get("candidates") or []
                    if not candidates:
                        continue
                    parts = candidates[0].get("content", {}).get("parts") or []
                    out = "".join(p.get("text", "") for p in parts).strip()
                    meta = data.get("usageMetadata") or {}
                    pt = int(meta.get("promptTokenCount") or 0)
                    ct = int(meta.get("candidatesTokenCount") or 0)
                    tt = int(meta.get("totalTokenCount") or (pt + ct))
                    if not tt:
                        pt = estimate_tokens(text)
                        ct = estimate_tokens(out)
                        tt = pt + ct
                    if out:
                        self.model = model
                        self.last_usage = LLMCallUsage(
                            provider=self.name,
                            model=model,
                            prompt_tokens=pt,
                            completion_tokens=ct,
                            total_tokens=tt,
                            ok=True,
                        )
                        return out
                except Exception as exc:  # noqa: BLE001
                    last_err = exc
                    self.last_usage = LLMCallUsage(
                        provider=self.name,
                        model=model,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}"[:200],
                    )
                    continue
        if last_err:
            raise last_err
        return ""


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
        model = os.getenv("VULN_AGENT_GEMINI_MODEL", "gemini-flash-latest")
        return GeminiProvider(api_key, model=model)

    return NullLLM()
