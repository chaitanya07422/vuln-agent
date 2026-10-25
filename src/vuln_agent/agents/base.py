from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from vuln_agent.core.context import ScanContext


@runtime_checkable
class Agent(Protocol):
    name: str
    requires_tags: List[str]
    skip_if_tags: List[str]

    async def run(self, ctx: ScanContext) -> None: ...


class BaseAgent:
    name: str = "base"
    requires_tags: List[str] = []
    skip_if_tags: List[str] = []

    async def run(self, ctx: ScanContext) -> None:
        raise NotImplementedError
