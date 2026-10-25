from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, HttpUrl

from vuln_agent.core.errors import ScanNotFoundError

router = APIRouter(prefix="/v1/scans", tags=["scans"])


class ScanCreate(BaseModel):
    url: HttpUrl
    attested: bool = Field(
        ...,
        description="Must be true — you own or are authorized to test this site",
    )


class ScanSummary(BaseModel):
    id: str
    url: str
    status: str
    created_at: str
    finished_at: Optional[str] = None
    fingerprint: Dict[str, Any] = Field(default_factory=dict)
    findings: list = Field(default_factory=list)
    error: Optional[str] = None


@router.post("", response_model=ScanSummary, status_code=202)
async def create_scan(body: ScanCreate, request: Request) -> Dict[str, Any]:
    lead = request.app.state.lead
    try:
        record = await lead.start_scan(url=str(body.url), attested=body.attested)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record


@router.get("/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: str, request: Request) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        return await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc


@router.get("/{scan_id}/report.md")
async def get_report(scan_id: str, request: Request) -> PlainTextResponse:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    md = scan.get("report_md")
    if not md:
        raise HTTPException(status_code=409, detail="report not ready")
    return PlainTextResponse(md, media_type="text/markdown")


@router.get("/{scan_id}/audit.json")
async def get_audit(scan_id: str, request: Request) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    return {"id": scan_id, "audit": scan.get("audit") or []}
