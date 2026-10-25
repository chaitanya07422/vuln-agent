from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    agent: str
    severity: Severity
    title: str
    evidence_url: Optional[str] = None
    evidence_snippet: Optional[str] = None
    explanation: Optional[str] = None
    fix: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
