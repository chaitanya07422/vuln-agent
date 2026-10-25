from __future__ import annotations

from vuln_agent.agents.base import BaseAgent
from vuln_agent.agents.playbook_runner import run_http_steps
from vuln_agent.core.context import ScanContext


class UploadAgent(BaseAgent):
    name = "upload"
    requires_tags: list = []
    skip_if_tags: list = ["unreachable"]

    async def run(self, ctx: ScanContext) -> None:
        tags = list((ctx.fingerprint or {}).get("tags") or [])
        steps = ctx.playbooks.section(tags, "upload") if ctx.playbooks else []
        extra = [
            {
                "path": "/api/presign",
                "method": "GET",
                "severity": "medium",
                "title": "Presign upload API responds",
                "finding_if_status": [200, 401, 403],
                "fix": "Require auth for presigned upload URLs.",
            },
            {
                "path": "/api/uploads",
                "method": "GET",
                "severity": "medium",
                "title": "Uploads API responds",
                "finding_if_status": [200, 401, 403],
                "fix": "Require auth for upload APIs.",
            },
        ]
        await run_http_steps(ctx, agent_name=self.name, steps=list(steps) + extra)
