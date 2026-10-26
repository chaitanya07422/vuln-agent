from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from vuln_agent.llm.base import LLMProvider, NullLLM
from vuln_agent.llm.usage import LLMCallUsage, summarize_usage

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
        self.usage_log: List[LLMCallUsage] = []

    def provider_name(self, role: Role) -> str:
        p = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        return getattr(p, "name", "null")

    def provider_model(self, role: Role) -> str:
        p = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        return str(getattr(p, "model", "") or getattr(p, "name", "null"))

    def usage_summary(self) -> Dict[str, Any]:
        summary = summarize_usage(self.usage_log)
        summary["roles"] = {
            role: {
                "provider": self.provider_name(role),  # type: ignore[arg-type]
                "model": self.provider_model(role),  # type: ignore[arg-type]
            }
            for role in ("lead", "adapt", "reporter")
        }
        return summary

    def _record(self, role: str, provider: LLMProvider, *, ok: bool, error: Optional[str] = None) -> None:
        usage = getattr(provider, "last_usage", None)
        if isinstance(usage, LLMCallUsage):
            usage.role = role
            if not ok and error:
                usage.ok = False
                usage.error = error
            self.usage_log.append(usage)
            return
        self.usage_log.append(
            LLMCallUsage(
                provider=getattr(provider, "name", "unknown"),
                model=str(getattr(provider, "model", "") or ""),
                role=role,
                ok=ok,
                error=error,
            )
        )

    async def complete(self, role: Role, prompt: str, *, system: Optional[str] = None) -> str:
        provider = self.mapping.get(role) or self.mapping.get("fallback") or NullLLM()
        try:
            text = await provider.complete(prompt, system=system)
            self._record(role, provider, ok=bool(text))
            if text:
                return text
        except Exception as exc:  # noqa: BLE001
            self._record(role, provider, ok=False, error=f"{type(exc).__name__}: {exc}"[:200])
        fallback = self.mapping.get("fallback") or NullLLM()
        if fallback is provider:
            return ""
        try:
            text = await fallback.complete(prompt, system=system)
            self._record("fallback", fallback, ok=bool(text))
            return text
        except Exception as exc:  # noqa: BLE001
            self._record("fallback", fallback, ok=False, error=f"{type(exc).__name__}: {exc}"[:200])
            return ""
