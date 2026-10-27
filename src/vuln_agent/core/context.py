from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

from vuln_agent.core.finding import Finding


@dataclass
class Scope:
    host: str
    scheme: str
    allow_hosts: List[str]

    @classmethod
    def from_url(cls, url: str) -> "Scope":
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("url must be http(s) with a host")
        host = parsed.hostname.lower()
        return cls(host=host, scheme=parsed.scheme, allow_hosts=[host])


@dataclass
class ScanContext:
    scan_id: str
    url: str
    scope: Scope
    tools: Any
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    audit: List[Dict[str, Any]] = field(default_factory=list)
    playbooks: Any = None
    llm: Any = None
    report_md: Optional[str] = None
    risk_path: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    emit: Optional[Callable[[Finding], Awaitable[None]]] = None
    record_audit: Optional[Callable[..., Awaitable[None]]] = None
    # Persist partial report/findings mid-scan (e.g. template brief before LLM polish).
    persist_partial: Optional[Callable[..., Awaitable[None]]] = None

    async def emit_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.emit:
            await self.emit(finding)

    async def audit_event(self, **payload: Any) -> None:
        self.audit.append(payload)
        if self.record_audit:
            await self.record_audit(**payload)

    async def save_partial(self, **fields: Any) -> None:
        if self.persist_partial:
            await self.persist_partial(**fields)
