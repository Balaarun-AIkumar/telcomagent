"""Gateway: authN (G0), chat, secret-by-reference redemption (G4), break-glass, rate limiting (G8)."""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import audit, auth, confirmations, idg, legacy, orchestrator, reveal, telemetry, tools
from .context import Principal, current_principal, new_trace_id
from .core import connect, init_platform, now
from .datagen import service_token
from .policy import pdp

app = FastAPI(title="Switchboard gateway")
_hits: dict[str, deque] = defaultdict(deque)
RATE = 30  # requests per minute per user
UI = Path(__file__).parent / "data" / "ui" / "index.html"


@app.on_event("startup")
def start_permit_sync_worker() -> None:
    init_platform()
    if os.getenv("PERMIT_API_KEY"):
        with connect("platform") as c:
            idg.enqueue_current_state(c)
        idg.start_sync_worker()


@app.on_event("shutdown")
def stop_permit_sync_worker() -> None:
    idg.stop_sync_worker()
    from . import policy

    if hasattr(policy._pdp, "_expiry_stop"):
        policy._pdp._expiry_stop.set()
    policy._pdp = None


def dev_only() -> None:
    """Dev helpers (token minting, WO toggles, span viewer). Set SB_DEV_ENDPOINTS=0 in any shared deployment."""
    if os.getenv("SB_DEV_ENDPOINTS", "0") != "1":
        raise HTTPException(404, "not found")


def principal(authorization: str = Header(default="")) -> Principal:
    try:
        p = auth.principal_from_token(authorization.removeprefix("Bearer ").strip())
    except Exception:
        raise HTTPException(401, "invalid or missing token") from None  # fail closed, no detail echoed
    q, t = _hits[p.user_id], time.monotonic()
    while q and t - q[0] > 60:
        q.popleft()
    if len(q) >= RATE:
        raise HTTPException(429, "rate limit exceeded")
    q.append(t)
    return p


@app.exception_handler(HTTPException)
async def problem_json(_, exc: HTTPException):
    return JSONResponse({"type": "about:blank", "title": exc.detail, "status": exc.status_code},
                        status_code=exc.status_code, media_type="application/problem+json")


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    message: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(default="default", min_length=1, max_length=64)


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation_ref: str = Field(min_length=10, max_length=100)


class TokenIn(BaseModel):
    user_id: str


class BreakGlassIn(BaseModel):
    approver_token: str
    cpe_sn: str
    justification: str = Field(min_length=10, max_length=500)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", include_in_schema=False)
def ui():
    return FileResponse(UI)


@app.get("/dev/users", dependencies=[Depends(dev_only)])
def dev_users():
    with connect("platform") as c:
        return [dict(r) for r in c.execute("SELECT user_id, display, role, tenant FROM app_user")]


@app.post("/dev/work-orders/{wo_id}/{status}", dependencies=[Depends(dev_only)])
def dev_set_wo(wo_id: str, status: str):
    """Simulate an operational event (e.g. technician closes the job), then run idg-sync."""
    if status not in ("IN_PROGRESS", "COMPLETED"):
        raise HTTPException(400, "status must be IN_PROGRESS or COMPLETED")
    try:
        idg.set_wo_status(wo_id, status)
    except KeyError:
        raise HTTPException(404, "unknown work order") from None
    return {"work_order": wo_id, "status": status, "published": idg.sync_once()}


@app.post("/dev/trace2test/{trace_id}", dependencies=[Depends(dev_only)])
def dev_trace2test(trace_id: str):
    """Save a trace seen in the UI as a replayable regression fixture."""
    from . import debugtools

    if not trace_id.isalnum():
        raise HTTPException(400, "invalid trace id")
    try:
        return {"saved": str(debugtools.export(trace_id))}
    except KeyError:
        raise HTTPException(404, "trace not found") from None


@app.get("/dev/observability", dependencies=[Depends(dev_only)])
def dev_observability():
    """Recent (already scrubbed) spans + metrics + audit chain status."""
    return {"spans": list(telemetry.SPAN_LOG)[-25:], "metrics": dict(telemetry.METRICS),
            "outbox_lag_seconds": idg.outbox_lag_seconds(), "audit_chain_intact": audit.verify_chain()}


@app.get("/.well-known/jwks.json")
def jwks():
    return auth.jwks()


@app.post("/dev/token", dependencies=[Depends(dev_only)])
def dev_token(body: TokenIn):
    """DEV ONLY: mint a token for a synthetic persona."""
    try:
        return {"access_token": auth.issue(body.user_id), "token_type": "Bearer"}
    except PermissionError:
        raise HTTPException(404, "unknown user") from None


@app.post("/v1/chat")
async def chat(body: ChatIn, p: Principal = Depends(principal)):
    return await orchestrator.arun(body.message, p, body.session_id)


@app.post("/v1/reveal/{ref}")
def reveal_psk(ref: str, p: Principal = Depends(principal)):
    trace_id = new_trace_id()
    with telemetry.span("gateway.reveal", **{"enduser.pseudo_id": telemetry.pseudo_id(p.user_id)}) as sp:
        grant = reveal.redeem(ref, p.user_id)
        if grant is None:
            telemetry.incr("reveal_grants_total{outcome=invalid}")
            audit.record(p.user_id, "reveal_credential", "grant:?", "deny", {"reason_code": "GRANT_INVALID"}, trace_id)
            raise HTTPException(403, "reveal not available")
        step_up_age = now() - (p.auth_time or 0)
        d = pdp().check(p, "reveal_credential", {"type": "cpe_device", "key": grant["cpe_sn"]},
                        {"step_up_age_s": step_up_age})  # TOCTOU re-check at redemption
        telemetry.set_attr(sp, "switchboard.policy.decision", "allow" if d.allowed else "deny")
        audit.record(p.user_id, "reveal_credential", f"cpe_device:{grant['cpe_sn']}",
                     ("break_glass" if d.reason_code == "BREAK_GLASS" else "allow") if d.allowed else "deny",
                     {"reason_code": d.reason_code, "work_order": grant["work_order"]}, trace_id)
        if not d.allowed:
            raise HTTPException(403, "reveal not available")
        try:
            r = legacy.call("acs", "GET", f"/acs/v1/devices/{grant['cpe_sn']}/secret",
                            headers={"X-Service-Token": service_token()})
            r.raise_for_status()
            secret = r.json()["Device.WiFi.AccessPoint.1.Security.KeyPassphrase"]
        except Exception:
            raise HTTPException(503, "reveal service unavailable; request a new reveal card") from None
        telemetry.incr("reveal_grants_total{outcome=redeemed}")
        # returned to the UI only: never to the orchestrator, memory, state or span attributes
        return JSONResponse({"cpe_sn": grant["cpe_sn"],
                             "psk": secret},
                            headers={"Cache-Control": "no-store"})


@app.post("/v1/break-glass")
def break_glass(body: BreakGlassIn, p: Principal = Depends(principal)):
    try:
        approver = auth.principal_from_token(body.approver_token)
    except Exception:
        raise HTTPException(401, "invalid approver token") from None
    if p.role != "supervisor" or approver.role != "supervisor" or approver.user_id == p.user_id:
        raise HTTPException(403, "two distinct supervisors required")
    trace_id = new_trace_id()
    ok = idg.break_glass(p.user_id, approver.user_id, body.cpe_sn, body.justification)
    audit.record(p.user_id, "break_glass", f"cpe_device:{body.cpe_sn}", "break_glass" if ok else "deny",
                 {"approver": approver.user_id, "justification": body.justification, "ttl_min": 15}, trace_id)
    with telemetry.span("gateway.break_glass", **{"switchboard.policy.decision": "break_glass"}):
        pass
    if not ok:
        raise HTTPException(400, "break-glass rejected")
    return {"status": "granted", "expires_in_min": 15, "review": "queued"}


@app.post("/v1/confirm/{action}")
def confirm(action: str, body: ConfirmIn, p: Principal = Depends(principal)):
    """Redeem one user/action/arguments-bound token, then authorize the write again."""
    if action not in {"trigger_psk_reset", "reboot_device"}:
        raise HTTPException(404, "unknown action")
    args = confirmations.consume(body.confirmation_ref, p.user_id, action)
    if args is None:
        raise HTTPException(403, "confirmation expired or unavailable")
    token = current_principal.set(p)
    approved = confirmations.approved_action.set((action, args))
    new_trace_id()
    try:
        result = tools.call_tool(action, args)
    finally:
        confirmations.approved_action.reset(approved)
        current_principal.reset(token)
    text = ("Done. A new Wi-Fi password was sent to the account holder's number on file."
            if action == "trigger_psk_reset" else "The device reboot was requested.")
    return {**result, "text": text if result.get("status") == "ok" else "The action could not be completed."}


@app.get("/v1/explain/{user_id}/{cpe_sn}")
def explain(user_id: str, cpe_sn: str, p: Principal = Depends(principal)):
    if p.role != "supervisor":
        raise HTTPException(403, "supervisor only")
    return {"paths": idg.explain_access(user_id, cpe_sn)}
