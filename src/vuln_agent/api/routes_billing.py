from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from vuln_agent.auth.deps import effective_plan, require_user
from vuln_agent.auth.tokens import public_user

router = APIRouter(prefix="/v1/billing", tags=["billing"])

PRODUCT_ID = "scanlead"


class CheckoutBody(BaseModel):
    interval: str = "month"  # month | year


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
            return {"plan": "free", "active": False, "expires_at": None}
        return res.json()


async def sync_user_plan(request: Request, user: Dict[str, Any]) -> Dict[str, Any]:
    """Pull entitlement from payments-service into local user.plan."""
    try:
        ent = await _fetch_entitlement(user["id"])
    except Exception:
        return user
    if ent.get("active") and ent.get("plan") == "pro":
        if user.get("plan") != "pro" or user.get("plan_expires_at") != ent.get("expires_at"):
            user = await request.app.state.users.update(
                user["id"],
                plan="pro",
                plan_expires_at=ent.get("expires_at"),
            )
    elif user.get("plan") == "pro" and not ent.get("active"):
        user = await request.app.state.users.update(
            user["id"],
            plan="free",
            plan_expires_at=None,
        )
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
            {"id": "free", "name": "Free", "price": 0, "history": 10, "pdf": False},
            {
                "id": "pro_monthly",
                "name": "Pro",
                "interval": "month",
                "price": 999,
                "history": 500,
                "pdf": True,
            },
            {
                "id": "pro_yearly",
                "name": "Pro yearly",
                "interval": "year",
                "price": 7999,
                "history": 500,
                "pdf": True,
            },
        ],
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
    plan_id = "pro_yearly" if body.interval == "year" else "pro_monthly"
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
    return {
        "user": public_user(user),
        "plan": effective_plan(user),
        "history_limit": 500 if effective_plan(user) == "pro" else 10,
        "pdf": effective_plan(user) == "pro",
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
    return {
        "user": public_user(user),
        "plan": effective_plan(user),
        "history_limit": 500 if effective_plan(user) == "pro" else 10,
        "pdf": effective_plan(user) == "pro",
    }
