from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List


async def dig_records(host: str, rtype: str) -> Dict[str, Any]:
    """Query DNS via dig when available. Detect-only; no zone transfer flood."""
    dig = shutil.which("dig")
    if not dig:
        return {"ok": False, "error": "dig_unavailable", "records": []}

    def _run() -> Dict[str, Any]:
        import subprocess

        try:
            proc = subprocess.run(
                [dig, "+short", rtype, host],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc), "records": []}
        lines = [ln.strip().strip('"') for ln in (proc.stdout or "").splitlines() if ln.strip()]
        return {"ok": proc.returncode == 0, "records": lines, "rtype": rtype, "host": host}

    return await asyncio.to_thread(_run)


async def dig_cname(host: str) -> Dict[str, Any]:
    return await dig_records(host, "CNAME")


async def dig_axfr_refused(host: str) -> Dict[str, Any]:
    """Single AXFR attempt — expect refuse/fail. Never retries."""
    dig = shutil.which("dig")
    if not dig:
        return {"ok": False, "error": "dig_unavailable", "refused": None}

    def _run() -> Dict[str, Any]:
        import subprocess

        try:
            proc = subprocess.run(
                [dig, "AXFR", host],
                capture_output=True,
                text=True,
                timeout=6,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc), "refused": None}
        out = ((proc.stdout or "") + (proc.stderr or "")).lower()
        refused = any(
            x in out
            for x in ("transfer failed", "refused", "not allowed", "failed", "timed out", "connection")
        )
        # Success with many SOA/NS lines would be a problem
        lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip() and not ln.startswith(";")]
        open_axfr = proc.returncode == 0 and len(lines) > 5 and not refused
        return {
            "ok": True,
            "refused": refused and not open_axfr,
            "open_axfr": open_axfr,
            "line_count": len(lines),
        }

    return await asyncio.to_thread(_run)


def txt_has_spf(records: List[str]) -> bool:
    return any(r.lower().startswith("v=spf1") for r in records)


def txt_has_dmarc(records: List[str]) -> bool:
    return any(r.lower().startswith("v=dmarc1") for r in records)
