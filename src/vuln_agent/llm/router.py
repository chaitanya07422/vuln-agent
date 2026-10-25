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

    async def complete(self, role: Role, prompt: str, *, system: Optional[str] = None) -> str:
        provider = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        try:
            return await provider.complete(prompt, system=system)
        except Exception:
            fallback = self.mapping.get("fallback") or NullLLM()
            return await fallback.complete(prompt, system=system)
