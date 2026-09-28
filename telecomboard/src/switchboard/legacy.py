"""Simulated legacy REST estate (deliberately quirky) + resilient client (retries, circuit breaker, chaos toggles)."""
from __future__ import annotations

import asyncio
import json
import os
import random
import secrets
import threading
import time

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .core import connect, now
from .datagen import _psk, fernet, service_token


def problem(status: int, title: str) -> JSONResponse:
    return JSONResponse({"type": "about:blank", "title": title, "status": status}, status_code=status,
                        media_type="application/problem+json")


def _chaos(app: FastAPI) -> None:
    @app.middleware("http")
    async def chaos(request: Request, call_next):
        from . import telemetry

        telemetry.adopt_traceparent(request.headers.get("traceparent"))
        if (ms := float(os.getenv("SB_CHAOS_LATENCY_MS", "0"))) > 0:
            await asyncio.sleep(random.uniform(0, ms) / 1000)
        if random.random() < float(os.getenv("SB_CHAOS_5XX", "0")):
            return problem(503, "chaos: upstream unavailable")
        with telemetry.span(f"legacy.{app.title.split()[0]}", **{"http.route": request.url.path}):
            return await call_next(request)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}


# ---------------- prov-api: XML-ish text over a CGI-style endpoint ----------------
prov_api = FastAPI(title="prov-api (legacy)")
_chaos(prov_api)


@prov_api.post("/cgi-bin/prov.do", response_class=PlainTextResponse)
def prov_do(action: str, sn: str):
    if action != "PSKRST":
        return PlainTextResponse("RESULT=9|MSG=BAD ACTION", status_code=200)
    with connect("legacy") as c:
        if not c.execute("SELECT 1 FROM wln_cfg WHERE cpe_sn=?", (sn,)).fetchone():
            return "RESULT=4|MSG=SN NOT FOUND"
        c.execute("UPDATE wln_cfg SET psk_enc=?, upd_ts=datetime('now') WHERE cpe_sn=?",
                  (fernet().encrypt(_psk(random.Random()).encode()), sn))
    return f"RESULT=0|MSG=PSK RESET, SMS QUEUED TO NUMBER ON FILE|TXN={secrets.token_hex(4).upper()}"


# ---------------- acs-lite: TR-181 parameter tree ----------------
acs_lite = FastAPI(title="acs-lite")
_chaos(acs_lite)


@acs_lite.get("/acs/v1/devices/{sn}/parameters")
def acs_params(sn: str):
    with connect("legacy") as c:
        cpe = c.execute("SELECT c.*, o.rx_pwr_dbm FROM cpe_inv c LEFT JOIN ont_inv o ON o.ont_id=c.ont_id"
                        " WHERE cpe_sn=?", (sn,)).fetchone()
        w = c.execute("SELECT ssid_txt FROM wln_cfg WHERE cpe_sn=? AND radio_idx=1", (sn,)).fetchone()
    if not cpe:
        return problem(404, "device not found")
    los = cpe["rx_pwr_dbm"] is not None and cpe["rx_pwr_dbm"] < -28
    return {"Device.DeviceInfo.ModelName": cpe["mdl_cd"], "Device.DeviceInfo.SoftwareVersion": cpe["fw_ver"],
            "Device.Optical.Interface.1.Status": "LOS" if los else "Up",
            "Device.Optical.Interface.1.OpticalSignalLevel": cpe["rx_pwr_dbm"],
            "Device.WiFi.SSID.1.SSID": w["ssid_txt"] if w else None,
            "Device.WiFi.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
            "Device.WiFi.AccessPoint.1.Security.KeyPassphrase": "<write-only>"}


@acs_lite.get("/acs/v1/devices/{sn}/secret")
def acs_secret(sn: str, x_service_token: str = Header(default="")):
    if not secrets.compare_digest(x_service_token, service_token()):
        return problem(403, "service identity required")
    with connect("legacy") as c:
        w = c.execute("SELECT psk_enc FROM wln_cfg WHERE cpe_sn=? AND radio_idx=1", (sn,)).fetchone()
    if not w:
        return problem(404, "device not found")
    return {"Device.WiFi.AccessPoint.1.Security.KeyPassphrase": fernet().decrypt(w[0]).decode()}


@acs_lite.post("/acs/v1/devices/{sn}/reboot")
def acs_reboot(sn: str):
    return {"sn": sn, "status": "reboot_scheduled"}


# ---------------- ticketing-api: TMF621 subset ----------------
ticketing_api = FastAPI(title="ticketing-api (TMF621 subset)")
_chaos(ticketing_api)
BASE = "/tmf-api/troubleTicket/v4/troubleTicket"


def _tt(r) -> dict:
    return {"id": r["tt_id"], "description": r["descr"], "status": r["status"], "ticketType": r["queue"],
            "relatedEntity": [{"id": r["sbscr_ref"], "@referredType": "Customer"}],
            "note": [{"text": n} for n in json.loads(r["notes"] or "[]")], "creationDate": r["created"]}


@ticketing_api.get(BASE)
def list_tickets(relatedEntity: str | None = None, limit: int = 20):
    with connect("legacy") as c:
        rows = c.execute("SELECT * FROM tkt WHERE (? IS NULL OR sbscr_ref = ?) ORDER BY created DESC LIMIT ?",
                         (relatedEntity, relatedEntity, min(limit, 100))).fetchall()
    return [_tt(r) for r in rows]


@ticketing_api.get(BASE + "/{tt_id}")
def get_ticket(tt_id: str):
    with connect("legacy") as c:
        r = c.execute("SELECT * FROM tkt WHERE tt_id=?", (tt_id,)).fetchone()
    return _tt(r) if r else problem(404, "ticket not found")


@ticketing_api.post(BASE, status_code=201)
async def create_ticket(request: Request, idempotency_key: str = Header(default="")):
    body = await request.json()
    if not idempotency_key:
        return problem(400, "Idempotency-Key header required")
    with connect("legacy") as c:
        prior = c.execute("SELECT * FROM tkt WHERE idem_key=?", (idempotency_key,)).fetchone()
        if prior:
            return _tt(prior)
        tt_id = f"TT-{c.execute('SELECT COUNT(*) FROM tkt').fetchone()[0] + 5001}"
        c.execute("INSERT INTO tkt VALUES (?,?,?,?,?,?,?,?)",
                  (tt_id, body.get("customer_id"), body.get("ticketType", "field"), "open", body.get("description", ""),
                   "[]", idempotency_key, time.strftime("%Y%m%d%H%M%S", time.gmtime(now()))))
        return _tt(c.execute("SELECT * FROM tkt WHERE tt_id=?", (tt_id,)).fetchone())


@ticketing_api.post(BASE + "/{tt_id}/note", status_code=201)
async def add_ticket_note(tt_id: str, request: Request):
    text = str((await request.json()).get("text", ""))[:1000]
    with connect("legacy") as c:
        r = c.execute("SELECT notes FROM tkt WHERE tt_id=?", (tt_id,)).fetchone()
        if not r:
            return problem(404, "ticket not found")
        c.execute("UPDATE tkt SET notes=? WHERE tt_id=?", (json.dumps([*json.loads(r[0] or "[]"), text]), tt_id))
    return {"id": tt_id, "status": "note_added"}


# ---------------- resilient client ----------------
APPS = {"prov": prov_api, "acs": acs_lite, "ticketing": ticketing_api}
_clients: dict[str, tuple[object, threading.Lock]] = {}
_breaker: dict[str, list[float]] = {}
_cassette_lock = threading.Lock()


class UpstreamError(RuntimeError):
    pass


def _client(service: str):
    if service not in _clients:
        url = os.getenv(f"SB_{service.upper()}_URL")
        if url:
            cl = httpx.Client(base_url=url, timeout=5)
        else:
            from fastapi.testclient import TestClient

            cl = TestClient(APPS[service], raise_server_exceptions=False)
        _clients[service] = (cl, threading.Lock())
    return _clients[service]


def _cassette_key(service: str, method: str, path: str, kw: dict) -> str:
    return json.dumps([service, method, path, kw.get("params"), kw.get("json")], sort_keys=True, default=str)


def _cassette() -> tuple[str | None, dict]:
    """SB_CASSETTE=<file> with SB_CASSETTE_MODE=record|replay separates model variance from environment variance."""
    path = os.getenv("SB_CASSETTE")
    if not path:
        return None, {}
    try:
        with open(path, encoding="utf-8") as f:
            return path, json.load(f)
    except FileNotFoundError:
        return path, {}


def call(service: str, method: str, path: str, *, retries: int = 3, **kw) -> httpx.Response:
    cpath, tape = (None, {}) if path.endswith("/secret") else _cassette()
    key = _cassette_key(service, method, path, kw)
    if cpath and os.getenv("SB_CASSETTE_MODE") == "replay":
        if key not in tape:
            raise UpstreamError(f"{service}: not in cassette")
        rec = tape[key]
        return httpx.Response(rec["status"], content=rec["body"].encode(), headers={"content-type": rec["ctype"]})
    fails, opened = _breaker.setdefault(service, [0, 0.0])
    if fails >= 5 and now() - opened < 30:
        raise UpstreamError(f"{service}: circuit open")
    cl, lock = _client(service)
    headers = kw.pop("headers", {})
    from .context import current_trace_id

    if tid := current_trace_id.get():
        headers["traceparent"] = f"00-{tid}-{secrets.token_hex(8)}-01"
    retries = retries if method.upper() in {"GET", "HEAD"} or headers.get("Idempotency-Key") else 1
    r = None
    for attempt in range(retries):
        try:
            with lock:
                r = cl.request(method, path, headers=headers, **kw)
        except httpx.TransportError:
            time.sleep(0.05 * 2**attempt)
            continue
        if r.status_code < 500:
            _breaker[service] = [0, 0.0]
            if cpath and os.getenv("SB_CASSETTE_MODE") == "record":
                with _cassette_lock:
                    _, tape = _cassette()
                    tape[key] = {"status": r.status_code, "body": r.text,
                                 "ctype": r.headers.get("content-type", "application/json")}
                    with open(cpath, "w", encoding="utf-8") as f:
                        json.dump(tape, f, indent=1)
            return r
        time.sleep(0.05 * 2**attempt)
    _breaker[service] = [fails + 1, now()]
    raise UpstreamError(f"{service}: unavailable")
