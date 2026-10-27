from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from vuln_agent.auth.deps import effective_plan, require_user
from vuln_agent.auth.quotas import FREE_FULL_LIMIT, FREE_SCAN_LIMIT, history_limit
from vuln_agent.auth.tokens import public_user

router = APIRouter(prefix="/v1/billing", tags=["billing"])

PRODUCT_ID = "scanlead"


class CheckoutBody(BaseModel):
    interval: str = "month"  # month | year | once (deep brief)
    plan_id: Optional[str] = None  # optional override e.g. deep_scan_once


def _payments_url() -> str:
    return (os.getenv("PAYMENTS_SERVICE_URL") or "http://127.0.0.1:8100").rstrip("/")


def _payments_key() -> str:
    return os.getenv("PAYMENTS_KEY_SCANLEAD") or ""


def _payments_configured() -> bool:
    return bool(_payments_url())


async def _fetch_entitlement(user_id: str) -> Dict[str, Any]:
    headers = {}
    key = _payments_key()
    if key:
        headers["X-Product-Key"] = key
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.get(
            f"{_payments_url()}/v1/entitlements",
            params={"product_id": PRODUCT_ID, "user_ref": user_id},
            headers=headers,
        )
        if res.status_code >= 400:
            return {"plan": "free", "active": False, "expires_at": None, "deep_credits": 0}
        return res.json()


async def sync_user_plan(request: Request, user: Dict[str, Any]) -> Dict[str, Any]:
    """Pull entitlement from payments-service into local user.plan / deep_credits."""
    try:
        ent = await _fetch_entitlement(user["id"])
    except Exception:
        return user
    updates: Dict[str, Any] = {}
    if ent.get("active") and ent.get("plan") == "pro":
        if user.get("plan") != "pro" or user.get("plan_expires_at") != ent.get("expires_at"):
            updates["plan"] = "pro"
            updates["plan_expires_at"] = ent.get("expires_at")
    elif user.get("plan") == "pro" and not ent.get("active"):
        updates["plan"] = "free"
        updates["plan_expires_at"] = None

    credits = max(0, int(ent.get("deep_credits") or 0))
    if int(user.get("deep_credits") or 0) != credits:
        updates["deep_credits"] = credits

    if updates:
        user = await request.app.state.users.update(user["id"], **updates)
    return user


async def consume_deep_credit(request: Request, user: Dict[str, Any]) -> Dict[str, Any]:
    """Decrement one deep brief credit locally and in payments store when possible."""
    credits = max(0, int(user.get("deep_credits") or 0))
    if credits <= 0:
        raise HTTPException(status_code=402, detail="No deep brief credits remaining")
    new_credits = credits - 1
    user = await request.app.state.users.update(user["id"], deep_credits=new_credits)
    # Best-effort mirror to payments-service
    try:
        headers = {"Content-Type": "application/json"}
        key = _payments_key()
        if key:
            headers["X-Product-Key"] = key
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{_payments_url()}/v1/entitlements/consume-credit",
                headers=headers,
                json={"product_id": PRODUCT_ID, "user_ref": user["id"], "delta": 1},
            )
    except Exception:
        pass
    return user


@router.get("/plans")
async def plans() -> Dict[str, Any]:
    ready = False
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(f"{_payments_url()}/v1/products/{PRODUCT_ID}/plans")
            if res.status_code < 400:
                data = res.json()
                ready = bool(data.get("polar_ready") or data.get("mock_allowed"))
    except Exception:
        ready = False
    return {
        "currency": "INR",
        "plans": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "history": FREE_SCAN_LIMIT,
                "scans": FREE_FULL_LIMIT,
                "full_briefs": FREE_FULL_LIMIT,
                "pdf": False,
                "note": "2 full Free briefs after signup · then preview (1 finding) · guest 1 full + 1 preview",
            },
            {
                "id": "pro_monthly",
                "name": "Pro",
                "interval": "month",
                "price": 999,
                "history": 500,
                "scans": 500,
                "pdf": True,
            },
            {
                "id": "pro_yearly",
                "name": "Pro yearly",
                "interval": "year",
                "price": 7999,
                "history": 500,
                "scans": 500,
                "pdf": True,
            },
            {
                "id": "deep_scan_once",
                "name": "Deep brief",
                "interval": "once",
                "price": 60,
                "history": 0,
                "pdf": True,
                "credits": 1,
            },
        ],
        "guest_scans": 2,
        "payments_ready": ready,
        # backward-compatible alias for older UI
        "razorpay_ready": ready,
    }


@router.post("/checkout")
async def checkout(
    body: CheckoutBody,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    if not _payments_configured():
        raise HTTPException(status_code=503, detail="Payments service URL not configured")
    if body.plan_id == "deep_scan_once" or body.interval == "once":
        plan_id = "deep_scan_once"
    elif body.interval == "year":
        plan_id = "pro_yearly"
    else:
        plan_id = body.plan_id or "pro_monthly"
    front = os.getenv("VULN_AGENT_FRONTEND_URL", "http://localhost:3000").rstrip("/")
    headers = {"Content-Type": "application/json"}
    key = _payments_key()
    if key:
        headers["X-Product-Key"] = key
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.post(
            f"{_payments_url()}/v1/checkout",
            headers=headers,
            json={
                "product_id": PRODUCT_ID,
                "user_ref": user["id"],
                "plan_id": plan_id,
                "success_url": f"{front}/pricing?paid=1",
                "cancel_url": f"{front}/pricing?canceled=1",
                "customer_email": user.get("email"),
            },
        )
        if res.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"payments-service: {res.text[:240]}")
        data = res.json()
    return {
        "checkout_url": data.get("checkout_url"),
        "provider": data.get("provider"),
        "mock": data.get("mock", False),
        "plan_id": plan_id,
    }


@router.post("/sync")
async def sync_billing(
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    user = await sync_user_plan(request, user)
    plan = effective_plan(user)
    return {
        "user": public_user(user),
        "plan": plan,
        "deep_credits": int(user.get("deep_credits") or 0),
        "history_limit": history_limit(user),
        "full_briefs": FREE_FULL_LIMIT if plan != "pro" else history_limit(user),
        "pdf": plan == "pro" or int(user.get("deep_credits") or 0) > 0,
    }


@router.post("/webhook")
async def webhook_legacy() -> Dict[str, str]:
    """Razorpay webhook retired — Polar webhooks hit payments-service."""
    return {"ok": "retired", "hint": "POST /v1/webhooks/polar on payments-service"}


@router.get("/me")
async def billing_me(
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    user = await sync_user_plan(request, user)
    plan = effective_plan(user)
    return {
        "user": public_user(user),
        "plan": plan,
        "deep_credits": int(user.get("deep_credits") or 0),
        "history_limit": history_limit(user),
        "full_briefs": FREE_FULL_LIMIT if plan != "pro" else history_limit(user),
        "pdf": plan == "pro" or int(user.get("deep_credits") or 0) > 0,
    }
