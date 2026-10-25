from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import run_http_steps
from vuln_agent.core.context import ScanContext


class CorsApiAgent(BaseAgent):
    name = "cors_api"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        steps = ctx.playbooks.section(tags, "cors_api") if ctx.playbooks else []
        # CORS probes use Origin header + header match rules in playbook
        await run_http_steps(ctx, agent_name=self.name, steps=steps)
