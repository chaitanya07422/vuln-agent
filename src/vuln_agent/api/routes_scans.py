from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field, HttpUrl

from vuln_agent.api.routes_billing import consume_deep_credit, sync_user_plan
from vuln_agent.auth.deps import (
    effective_plan,
    optional_user,
    request_scan_source,
    require_user,
)
from vuln_agent.auth.quotas import (
    FREE_FULL_LIMIT,
    FREE_MCP_SCAN_LIMIT,
    FREE_SCAN_LIMIT,
    GUEST_FULL_LIMIT,
    GUEST_LIFETIME_LIMIT,
    PRO_SCAN_LIMIT,
    SCAN_SOURCE_MCP,
    SCAN_SOURCE_WEB,
    create_limit,
    history_limit,
    is_pro,
    pro_shares_quota,
    quota_payload,
)
from vuln_agent.auth.reveal import apply_reveal, choose_detail_level, teaser_report_md
from vuln_agent.core.errors import ScanNotFoundError
from vuln_agent.core.html_report import render_scan_html
from vuln_agent.core.scan_diff import diff_findings

router = APIRouter(prefix="/v1/scans", tags=["scans"])

GUEST_COOKIE = "scanlead_gid"


class ScanCreate(BaseModel):
    url: HttpUrl
    attested: bool = Field(
        ...,
        description="Must be true — you own or are authorized to test this site",
    )


class ClaimBody(BaseModel):
    claim_token: str


class AgentProgressRow(BaseModel):
    agent: str
    label: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    detail: Optional[str] = None
    step_at: Optional[str] = None


class ScanSummary(BaseModel):
    id: str
    url: str
    status: str
    created_at: str
    finished_at: Optional[str] = None
    fingerprint: Dict[str, Any] = Field(default_factory=dict)
    findings: list = Field(default_factory=list)
    risk_path: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    agents_progress: list[AgentProgressRow] = Field(default_factory=list)
    error: Optional[str] = None
    owner_id: Optional[str] = None
    claim_token: Optional[str] = None
    parent_scan_id: Optional[str] = None
    detail_level: Optional[str] = None
    hidden_findings: Optional[int] = None
    findings_total: Optional[int] = None


def _public_scan(
    scan: Dict[str, Any],
    *,
    include_claim: bool = False,
    viewer: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out = apply_reveal(dict(scan), viewer=viewer)
    if not include_claim:
        out.pop("claim_token", None)
    # never expose full audit in list/summary responses unless requested
    out.pop("audit", None)
    out.pop("report_md", None)
    return out


def _client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return request.client.host
    return ""


def _guest_id(request: Request) -> str:
    raw = (request.cookies.get(GUEST_COOKIE) or "").strip()
    if raw and len(raw) <= 64:
        return raw
    return secrets.token_urlsafe(18)


def _set_guest_cookie(response: Response, guest_id: str, *, secure: bool) -> None:
    response.set_cookie(
        key=GUEST_COOKIE,
        value=guest_id,
        max_age=60 * 60 * 24 * 400,  # ~13 months
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def _cookie_secure(request: Request) -> bool:
    if (request.headers.get("x-forwarded-proto") or "").lower() == "https":
        return True
    return request.url.scheme == "https"


def _free_exhausted_detail() -> Dict[str, Any]:
    return {
        "code": "FREE_QUOTA_EXCEEDED",
        "message": (
            f"Free includes {FREE_FULL_LIMIT} full briefs "
            f"(up to {FREE_SCAN_LIMIT} web scans). Upgrade to Pro or buy a ₹60 deep brief."
        ),
        "upgrade": {"pro": True, "deep": True},
        "limit": FREE_SCAN_LIMIT,
        "full_limit": FREE_FULL_LIMIT,
    }


def _mcp_exhausted_detail(*, plan: str) -> Dict[str, Any]:
    if plan == "pro":
        return {
            "code": "MCP_QUOTA_EXCEEDED",
            "message": f"MCP create quota reached. Contact support or wait.",
            "upgrade": {"pro": True},
            "limit": create_limit({"plan": "pro"}, source=SCAN_SOURCE_MCP),
        }
    return {
        "code": "MCP_QUOTA_EXCEEDED",
        "message": (
            f"Free includes {FREE_MCP_SCAN_LIMIT} MCP scan. "
            "Upgrade to Pro for a higher MCP quota (web Free scans are separate)."
        ),
        "upgrade": {"pro": True},
        "limit": FREE_MCP_SCAN_LIMIT,
    }


def _guest_exhausted_detail() -> Dict[str, Any]:
    return {
        "code": "GUEST_QUOTA_EXCEEDED",
        "message": (
            f"You used your {GUEST_LIFETIME_LIMIT} guest scans "
            f"(1 full + 1 preview). Sign in for {FREE_FULL_LIMIT} full Free briefs."
        ),
        "upgrade": {"signin": True},
        "limit": GUEST_LIFETIME_LIMIT,
        "full_limit": GUEST_FULL_LIMIT,
    }


@router.get("/quota")
async def get_quota(
    request: Request,
    response: Response,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    if user:
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
        plan = effective_plan(user)
        channel = request_scan_source(request)
        web_used = await store.count_by_owner(user["id"], source=SCAN_SOURCE_WEB)
        mcp_used = await store.count_by_owner(user["id"], source=SCAN_SOURCE_MCP)
        total_used = web_used + mcp_used
        if pro_shares_quota(user):
            # Pro: one shared pool — web and MCP both increment the same counter.
            limit = PRO_SCAN_LIMIT
            used = total_used
            remaining = max(0, limit - used)
            can = remaining > 0
            payload = quota_payload(
                mode=plan,
                limit=limit,
                used=used,
                deep_credits=int(user.get("deep_credits") or 0),
            )
            payload["channel"] = channel
            payload["shared"] = True
            payload["web"] = {
                "limit": limit,
                "used": web_used,
                "remaining": remaining,
                "can_scan": can,
            }
            payload["mcp"] = {
                "limit": limit,
                "used": mcp_used,
                "remaining": remaining,
                "can_scan": can,
            }
            return payload

        web_limit = create_limit(user, source=SCAN_SOURCE_WEB)
        mcp_limit = create_limit(user, source=SCAN_SOURCE_MCP)
        used = web_used if channel == SCAN_SOURCE_WEB else mcp_used
        limit = web_limit if channel == SCAN_SOURCE_WEB else mcp_limit
        payload = quota_payload(
            mode=plan,
            limit=limit,
            used=used,
            deep_credits=int(user.get("deep_credits") or 0),
            full_limit=FREE_FULL_LIMIT if channel == SCAN_SOURCE_WEB else mcp_limit,
            full_used=min(web_used, FREE_FULL_LIMIT)
            if channel == SCAN_SOURCE_WEB
            else mcp_used,
        )
        payload["channel"] = channel
        payload["shared"] = False
        payload["web"] = {
            "limit": web_limit,
            "used": web_used,
            "remaining": max(0, web_limit - web_used),
            "can_scan": web_used < web_limit,
        }
        payload["mcp"] = {
            "limit": mcp_limit,
            "used": mcp_used,
            "remaining": max(0, mcp_limit - mcp_used),
            "can_scan": mcp_used < mcp_limit,
        }
        # Top-level can_scan follows the auth channel (JWT→web, API key→mcp)
        payload["can_scan"] = payload[channel]["can_scan"]
        payload["remaining"] = payload[channel]["remaining"]
        payload["used"] = used
        payload["limit"] = limit
        return payload

    guest_id = _guest_id(request)
    if not request.cookies.get(GUEST_COOKIE):
        _set_guest_cookie(response, guest_id, secure=_cookie_secure(request))
    ip = _client_ip(request)
    used = await request.app.state.guest_quota.effective_used(guest_id, ip or None)
    return quota_payload(
        mode="guest",
        limit=GUEST_LIFETIME_LIMIT,
        used=used,
        deep_credits=0,
        full_limit=GUEST_FULL_LIMIT,
        full_used=min(used, GUEST_FULL_LIMIT),
    )


@router.post("", response_model=ScanSummary, status_code=202)
async def create_scan(
    body: ScanCreate,
    request: Request,
    response: Response,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    lead = request.app.state.lead
    store = request.app.state.store
    owner_id = user["id"] if user else None
    detail_level = "full"
    source = request_scan_source(request) if user else SCAN_SOURCE_WEB
    if user:
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
        if pro_shares_quota(user):
            count = await store.count_by_owner(owner_id)  # web + mcp
            limit = PRO_SCAN_LIMIT
        else:
            count = await store.count_by_owner(owner_id, source=source)
            limit = create_limit(user, source=source)
        if count >= limit:
            if is_pro(user):
                raise HTTPException(
                    status_code=429,
                    detail=f"Create quota reached ({limit}). Contact support or wait.",
                )
            if source == SCAN_SOURCE_MCP:
                raise HTTPException(
                    status_code=402,
                    detail=_mcp_exhausted_detail(plan=effective_plan(user)),
                )
            raise HTTPException(status_code=402, detail=_free_exhausted_detail())
        # Web keeps freemium full/teaser; Free MCP / Pro scans are full detail.
        if source == SCAN_SOURCE_MCP or is_pro(user):
            detail_level = "full"
        else:
            detail_level = choose_detail_level(
                plan=effective_plan(user),
                owner_scan_count=count,
                free_full_limit=FREE_FULL_LIMIT,
            )
    else:
        guest_id = _guest_id(request)
        ip = _client_ip(request)
        used = await request.app.state.guest_quota.effective_used(guest_id, ip or None)
        if used >= GUEST_LIFETIME_LIMIT:
            raise HTTPException(status_code=401, detail=_guest_exhausted_detail())
        detail_level = choose_detail_level(
            plan="guest",
            guest_used_before=used,
            guest_full_limit=GUEST_FULL_LIMIT,
        )
        await request.app.state.guest_quota.consume(guest_id, ip or None)
        _set_guest_cookie(response, guest_id, secure=_cookie_secure(request))

    try:
        record = await lead.start_scan(
            url=str(body.url),
            attested=body.attested,
            owner_id=owner_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = await store.update(record["id"], detail_level=detail_level, source=source)
    return _public_scan(record, include_claim=True, viewer=user)


@router.get("")
async def list_scans(
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    limit = history_limit(user)
    items = await store.list_by_owner(user["id"], limit=limit)
    slim = []
    for s in items:
        slim.append(
            {
                "id": s.get("id"),
                "url": s.get("url"),
                "status": s.get("status"),
                "created_at": s.get("created_at"),
                "finished_at": s.get("finished_at"),
                "summary": s.get("summary"),
                "parent_scan_id": s.get("parent_scan_id"),
            }
        )
    return {"scans": slim, "limit": limit, "plan": user.get("plan") or "free"}


@router.get("/{scan_id}", response_model=ScanSummary)
async def get_scan(
    scan_id: str,
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if user:
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
    return _public_scan(scan, viewer=user)


@router.post("/{scan_id}/claim", response_model=ScanSummary)
async def claim_scan(
    scan_id: str,
    body: ClaimBody,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if scan.get("owner_id") and scan.get("owner_id") != user["id"]:
        raise HTTPException(status_code=403, detail="scan owned by another user")
    if scan.get("owner_id") == user["id"]:
        return _public_scan(scan, viewer=user)
    if not scan.get("claim_token") or scan.get("claim_token") != body.claim_token:
        raise HTTPException(status_code=403, detail="invalid claim token")
    count = await store.count_by_owner(user["id"])
    if count >= history_limit(user):
        if is_pro(user):
            raise HTTPException(
                status_code=402,
                detail=f"Saved scan limit reached ({history_limit(user)}).",
            )
        raise HTTPException(status_code=402, detail=_free_exhausted_detail())
    updated = await store.update(scan_id, owner_id=user["id"], claim_token=None)
    return _public_scan(updated, viewer=user)


@router.post("/{scan_id}/retry", response_model=ScanSummary, status_code=202)
async def retry_failed_scan(
    scan_id: str,
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    """Re-run a failed scan without creating a new id / consuming quota again."""
    store = request.app.state.store
    lead = request.app.state.lead
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if scan.get("status") != "failed":
        raise HTTPException(status_code=409, detail="only failed scans can be retried")
    # Owner can always retry; guest/public share link can retry unowned scans.
    if scan.get("owner_id"):
        if not user or user.get("id") != scan.get("owner_id"):
            raise HTTPException(status_code=403, detail="only the owner can retry this scan")
    try:
        updated = await lead.retry_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _public_scan(updated, include_claim=True, viewer=user)


@router.post("/{scan_id}/rescan", status_code=202)
async def rescan(
    scan_id: str,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    lead = request.app.state.lead
    try:
        previous = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if previous.get("owner_id") != user["id"]:
        raise HTTPException(status_code=403, detail="only owner can rescan")
    # Rescan is tagged web; Pro still counts against the shared pool.
    source = SCAN_SOURCE_WEB
    if pro_shares_quota(user):
        count = await store.count_by_owner(user["id"])
        limit = PRO_SCAN_LIMIT
    else:
        count = await store.count_by_owner(user["id"], source=source)
        limit = create_limit(user, source=source)
    if count >= limit:
        if is_pro(user):
            raise HTTPException(status_code=429, detail=f"Create quota reached ({limit}).")
        raise HTTPException(status_code=402, detail=_free_exhausted_detail())
    detail_level = (
        "full"
        if is_pro(user)
        else choose_detail_level(
            plan=effective_plan(user),
            owner_scan_count=count,
            free_full_limit=FREE_FULL_LIMIT,
        )
    )
    record = await lead.start_scan(
        url=previous["url"],
        attested=True,
        owner_id=user["id"],
        parent_scan_id=scan_id,
    )
    record = await store.update(record["id"], detail_level=detail_level, source=source)
    return _public_scan(record, include_claim=True, viewer=user)


@router.post("/{scan_id}/unlock", response_model=ScanSummary)
async def unlock_scan(
    scan_id: str,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    """Spend one deep-brief credit to unlock full detail on a teaser scan."""
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    try:
        user = await sync_user_plan(request, user)
    except Exception:
        pass
    if scan.get("owner_id") and scan.get("owner_id") != user["id"]:
        raise HTTPException(status_code=403, detail="only the owner can unlock this scan")
    if is_pro(user) or scan.get("unlocked_full") or scan.get("branded_brief"):
        if not scan.get("owner_id"):
            scan = await store.update(scan_id, owner_id=user["id"], claim_token=None)
        return _public_scan(scan, viewer=user)
    await consume_deep_credit(request, user)
    fields: Dict[str, Any] = {
        "detail_level": "full",
        "unlocked_full": True,
        "branded_brief": True,
    }
    if not scan.get("owner_id"):
        fields["owner_id"] = user["id"]
        fields["claim_token"] = None
    updated = await store.update(scan_id, **fields)
    return _public_scan(updated, viewer=user)


@router.get("/{scan_id}/diff/{other_id}")
async def scan_diff(
    scan_id: str,
    other_id: str,
    request: Request,
) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        a = await store.get(scan_id)
        b = await store.get(other_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    # Treat scan_id as previous, other_id as current when other is newer
    if (b.get("created_at") or "") < (a.get("created_at") or ""):
        previous, current = b, a
    else:
        previous, current = a, b
    return {
        "previous_id": previous.get("id"),
        "current_id": current.get("id"),
        "diff": diff_findings(previous.get("findings") or [], current.get("findings") or []),
    }


@router.get("/{scan_id}/report.md")
async def get_report(
    scan_id: str,
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> PlainTextResponse:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if user:
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
    revealed = apply_reveal(scan, viewer=user)
    if revealed.get("detail_level") == "teaser":
        return PlainTextResponse(teaser_report_md(revealed), media_type="text/markdown")
    md = scan.get("report_md")
    if not md:
        raise HTTPException(status_code=409, detail="report not ready")
    return PlainTextResponse(md, media_type="text/markdown")


@router.get("/{scan_id}/report.html")
async def get_report_html(
    scan_id: str,
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> HTMLResponse:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if scan.get("status") != "done":
        raise HTTPException(status_code=409, detail="report not ready")
    branded = False
    if user and user.get("id") == scan.get("owner_id"):
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
        if is_pro(user) or scan.get("branded_brief") or scan.get("unlocked_full"):
            branded = True
        elif int(user.get("deep_credits") or 0) > 0 and (
            (scan.get("detail_level") or "full") == "teaser"
        ):
            # Spend one deep-brief credit → unlock full + branded HTML
            await consume_deep_credit(request, user)
            branded = True
            try:
                scan = await store.update(
                    scan_id,
                    branded_brief=True,
                    unlocked_full=True,
                    detail_level="full",
                )
            except Exception:
                pass
    revealed = apply_reveal(scan, viewer=user)
    if revealed.get("detail_level") == "teaser" and not branded:
        revealed["report_md"] = teaser_report_md(revealed)
        html_doc = render_scan_html(revealed, branded=False)
        return HTMLResponse(html_doc)
    html_doc = render_scan_html(scan, branded=branded)
    return HTMLResponse(html_doc)


@router.get("/{scan_id}/audit.json")
async def get_audit(
    scan_id: str,
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    store = request.app.state.store
    try:
        scan = await store.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if user:
        try:
            user = await sync_user_plan(request, user)
        except Exception:
            pass
    revealed = apply_reveal(scan, viewer=user)
    if revealed.get("detail_level") == "teaser":
        return {
            "id": scan_id,
            "audit": [],
            "detail_level": "teaser",
            "message": "Audit log locked on preview scans. Upgrade to Pro to unlock.",
        }
    return {"id": scan_id, "audit": scan.get("audit") or []}
