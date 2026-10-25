from __future__ import annotations

import importlib
from typing import Dict, List, Type

from vuln_agent.agents.base import Agent

# Add a feature: implement Agent + register here + enable in config/default.yaml
AGENT_ENTRYPOINTS: Dict[str, str] = {
    "recon": "vuln_agent.agents.recon:ReconAgent",
}


def _import_symbol(path: str) -> Type[Agent]:
    module_path, _, attr = path.partition(":")
    if not module_path or not attr:
        raise ValueError(f"invalid entrypoint: {path}")
    module = importlib.import_module(module_path)
    return getattr(module, attr)


def load_agents(enabled: List[str]) -> List[Agent]:
    agents: List[Agent] = []
    for name in enabled:
        entry = AGENT_ENTRYPOINTS.get(name)
        if not entry:
            raise KeyError(f"unknown agent '{name}' — add it to AGENT_ENTRYPOINTS")
        cls = _import_symbol(entry)
        agents.append(cls())
    return agents
