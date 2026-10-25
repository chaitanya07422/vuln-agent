from __future__ import annotations

import importlib
from typing import Dict, List, Type

from vuln_agent.agents.base import Agent

# Add feature: implement Agent + register here + enable in config/default.yaml
AGENT_ENTRYPOINTS: Dict[str, str] = {
    "recon": "vuln_agent.agents.recon:ReconAgent",
    "users": "vuln_agent.agents.users:UsersAgent",
    "auth": "vuln_agent.agents.auth:AuthAgent",
    "leaks": "vuln_agent.agents.leaks:LeaksAgent",
    "cors_api": "vuln_agent.agents.cors_api:CorsApiAgent",
    "upload": "vuln_agent.agents.upload:UploadAgent",
    "uat_app": "vuln_agent.agents.uat_app:UatAppAgent",
    "ports_mail": "vuln_agent.agents.ports_mail:PortsMailAgent",
    "adapt": "vuln_agent.agents.adapt:AdaptAgent",
    "reporter": "vuln_agent.agents.reporter:ReporterAgent",
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
