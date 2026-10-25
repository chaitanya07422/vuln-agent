from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Tool(Protocol):
    name: str

    async def __call__(self, **kwargs: Any) -> dict: ...
