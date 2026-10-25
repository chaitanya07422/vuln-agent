from __future__ import annotations

from typing import Dict, Literal, Optional

from vuln_agent.llm.base import LLMProvider, NullLLM

Role = Literal["lead", "adapt", "reporter"]


class LLMRouter:
    def __init__(self, mapping: Optional[Dict[str, LLMProvider]] = None) -> None:
        null = NullLLM()
        self.mapping: Dict[str, LLMProvider] = mapping or {
            "lead": null,
            "adapt": null,
            "reporter": null,
            "fallback": null,
        }

    def provider_name(self, role: Role) -> str:
        p = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        return getattr(p, "name", "null")

    async def complete(self, role: Role, prompt: str, *, system: Optional[str] = None) -> str:
        provider = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        try:
            text = await provider.complete(prompt, system=system)
            if text:
                return text
        except Exception:
            pass
        fallback = self.mapping.get("fallback") or NullLLM()
        if fallback is provider:
            return ""
        try:
            return await fallback.complete(prompt, system=system)
        except Exception:
            return ""
