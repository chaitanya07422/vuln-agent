from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import run_http_steps
from vuln_agent.core.context import ScanContext


class AuthAgent(BaseAgent):
    name = "auth"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        steps = ctx.playbooks.section(tags, "auth") if ctx.playbooks else []
        await run_http_steps(ctx, agent_name=self.name, steps=steps)
