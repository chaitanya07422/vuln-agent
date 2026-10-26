from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str: ...


class NullLLM:
    """Default: no external LLM calls. Swap via config later."""

    name = "null"
    model = "null"
    last_usage = None

    async def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        return ""
