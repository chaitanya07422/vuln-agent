from __future__ import annotations

from typing import Any, Dict, Optional

from vuln_agent.llm.providers import build_provider
from vuln_agent.llm.router import LLMRouter


def build_llm_router(llm_config: Optional[Dict[str, Any]] = None) -> LLMRouter:
    cfg = llm_config or {}
    return LLMRouter(
        {
            "lead": build_provider(cfg.get("lead")),
            "adapt": build_provider(cfg.get("adapt")),
            "reporter": build_provider(cfg.get("reporter")),
            "fallback": build_provider(cfg.get("fallback") or cfg.get("reporter") or cfg.get("lead")),
        }
    )
