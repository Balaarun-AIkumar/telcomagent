"""Tool layer shared by the orchestrator, ADK agents and MCP servers.
G2 (tool authZ) + G3 (data re-checks) + after-tool state validator. Denials carry reason codes + safe alternatives."""
from __future__ import annotations

import json
import inspect
import logging
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import get_type_hints

from pydantic import ConfigDict, Field, ValidationError, create_model

from . import a2a, audit, confirmations, kg, legacy, rag, reveal, telemetry, text2sql
from .context import Principal, current_trace_id, require_principal
from .core import connect, now
from .policy import CLASSIFICATION_LEVELS, ROLE_GRANTS, Decision, pdp
from .redaction import find_secrets, injection_score, scrub
from .logging_config import event

authorized_subjects: ContextVar[set[str] | None] = ContextVar("authorized_subjects", default=None)
NOT_AVAILABLE = {"status": "denied", "reason_code": "NOT_AVAILABLE",
                 "safe_alternatives": ["Open a ticket so an authorized team can follow up"]}


class PolicyUnavailable(RuntimeError):
    """A dependency outage is not an authorization denial or an empty search."""


@dataclass
class Tool:
    name: str
    fn: Callable[..., dict]
    action: str
    rtype: str
    key_arg: str | None = None
    read_only: bool = True
    destructive: bool = False
    description: str = ""

    def __post_init__(self):
        hints = get_type_hints(self.fn)
        fields = {name: (hints[name], ... if p.default is inspect.Parameter.empty else p.default)
                  for name, p in inspect.signature(self.fn).parameters.items() if name != "confirm"}
        patterns = {"subscriber_id": r"^S-\d{5}$", "cpe_sn": r"^CPE-\d+$", "ticket_id": r"^TT-\d+$",
                    "work_order_id": r"^WO-\d+$", "pon_port": r"^PON-\d{2}-\d{2}$", "ont_id": r"^ONT-\d+$"}
        for name, pattern in patterns.items():
            if name in fields:
                annotation, default = fields[name]
                fields[name] = (annotation, Field(default=default, pattern=pattern))
        self.args_model = create_model(self.name + "Input", __config__=ConfigDict(
            extra="forbid", strict=True, str_strip_whitespace=True, str_min_length=1, str_max_length=2000), **fields)


def check(p: Principal, action: str, rtype: str, key: str = "*", ctx: dict | None = None, tool: str = "") -> Decision:
    d = pdp().check(p, action, {"type": rtype, "key": key}, ctx or {})
    decision = "allow" if d.allowed else "deny"
    audit.record(p.user_id, action, f"{rtype}:{key}", decision, {"reason_code": d.reason_code, "tool": tool},
                 current_trace_id.get())
    telemetry.incr(f"policy_decisions_total{{decision={decision}}}")
    event("authorization", tool=tool, action=action, decision=decision, reason_code=d.reason_code)
    if d.reason_code == "POLICY_UNAVAILABLE":
        raise PolicyUnavailable()
    if d.allowed and rtype == "subscriber" and key != "*" and (s := authorized_subjects.get()) is not None:
        s.add(key)
    return d


def _denied(d: Decision) -> dict:
    return {"status": "denied", "reason_code": d.reason_code, "safe_alternatives": d.alternatives}


def _subscriber_for_cpe(cpe_sn: str) -> str | None:
    with connect("legacy") as c:
        r = c.execute("SELECT sbscr_ref FROM cpe_inv WHERE cpe_sn=?", (cpe_sn,)).fetchone()
    return r[0] if r else None


def scope_subscribers(p: Principal) -> list[str] | None:
    """Exact object scope. Sharing a postcode never grants access to a neighbour."""
    if ("subscriber", "read_profile") in ROLE_GRANTS.get(p.role, set()):
        return None
    with connect("platform") as c:
        rows = c.execute(
            "SELECT DISTINCT s.sbscr_id FROM pdp_tuple a JOIN pdp_tuple sv ON sv.subject = a.object"
            " AND sv.relation='serves' JOIN legacy.sub_mstr s ON 'subscriber:'||s.sbscr_id = sv.object"
            " WHERE a.subject=? AND a.relation='assignee'"
            " AND (a.expires_at IS NULL OR a.expires_at>?)"
            " AND (sv.expires_at IS NULL OR sv.expires_at>?)", (p.key, now(), now())).fetchall()
    return [r[0] for r in rows if check(p, "read_profile", "subscriber", r[0], tool="query_provisioning").allowed]


# ---------------- provisioning ----------------
def find_subscriber(address: str | None = None, subscriber_id: str | None = None) -> dict:
    p = require_principal()
    with connect("legacy") as c:
        rows = c.execute(
            "SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY acct_no ORDER BY crt_dt DESC) rn FROM sub_mstr"
            " WHERE acct_sts_cd <> 'X' AND (lower(svc_addr_1) = lower(?) OR sbscr_id = ?)) WHERE rn = 1 LIMIT 5",
            (address or "", subscriber_id or "")).fetchall()
        out = []
        for r in rows:
            if not check(p, "read_profile", "subscriber", r["sbscr_id"], tool="find_subscriber").allowed:
                continue
            devs = [dict(d) for d in c.execute("SELECT cpe_sn, mdl_cd AS model, fw_ver AS firmware, ont_id FROM cpe_inv"
                                              " WHERE sbscr_ref=?", (r["sbscr_id"],))]
            rec = {"subscriber_id": r["sbscr_id"], "status": {"A": "active", "S": "suspended", "T": "terminated",
                                                              "P": "pending"}.get(r["acct_sts_cd"]),
                   "service_zip": r["svc_addr_zip"], "devices": devs}
            if check(p, "read_pii", "subscriber", r["sbscr_id"], tool="find_subscriber").allowed:
                rec["name"], rec["service_address"] = r["nm_txt"], r["svc_addr_1"]
            out.append(rec)
    return {"status": "ok", "subscribers": out} if out else NOT_AVAILABLE


def get_work_orders(subscriber_id: str) -> dict:
    with connect("legacy") as c:
        rows = c.execute("SELECT wo_id, sts_cd, tenant FROM wo_hdr WHERE sbscr_ref=? AND sts_cd IN ('D','I')",
                         (subscriber_id,)).fetchall()
    m = {"D": "DISPATCHED", "I": "IN_PROGRESS"}
    return {"status": "ok", "work_orders": [{"id": r[0], "state": m[r[1]], "tenant": r[2]} for r in rows
            if check(require_principal(), "read", "work_order", r[0], tool="get_work_orders").allowed]}


def query_provisioning(question: str) -> dict:
    p = require_principal()
    scope = scope_subscribers(p)
    try:
        res = text2sql.answer(question, scope)
    except text2sql.SQLRejected as e:
        return {"status": "error", "error": str(e)}
    if scope is None and (s := authorized_subjects.get()) is not None:  # role-level readers may see any customer id
        s.update(v for row in res["rows"] for k, v in row.items() if k == "customer_id" and v)
    return {"status": "ok", **res}


def trigger_psk_reset(subscriber_id: str, confirm: bool = False) -> dict:
    if not confirm:
        return {"status": "needs_confirmation", "action": "trigger_psk_reset", "subscriber_id": subscriber_id}
    with connect("legacy") as c:
        cpe = c.execute("SELECT cpe_sn FROM cpe_inv WHERE sbscr_ref=?", (subscriber_id,)).fetchone()
    if not cpe:
        return NOT_AVAILABLE
    r = legacy.call("prov", "POST", "/cgi-bin/prov.do", params={"action": "PSKRST", "sn": cpe[0]})
    fields = dict(kv.split("=", 1) for kv in r.text.split("|"))
    return {"status": "ok" if fields.get("RESULT") == "0" else "error", "message": fields.get("MSG")}


# ---------------- acs ----------------
def get_device_status(cpe_sn: str) -> dict:
    r = legacy.call("acs", "GET", f"/acs/v1/devices/{cpe_sn}/parameters")
    if r.status_code != 200:
        return NOT_AVAILABLE
    j = r.json()
    return {"status": "ok", "cpe_sn": cpe_sn, "model": j["Device.DeviceInfo.ModelName"],
            "firmware": j["Device.DeviceInfo.SoftwareVersion"], "optical": j["Device.Optical.Interface.1.Status"],
            "rx_power_dbm": j["Device.Optical.Interface.1.OpticalSignalLevel"]}


def get_wifi_config(cpe_sn: str) -> dict:
    r = legacy.call("acs", "GET", f"/acs/v1/devices/{cpe_sn}/parameters")
    if r.status_code != 200:
        return NOT_AVAILABLE
    j = {k: v for k, v in r.json().items() if "KeyPassphrase" not in k}
    return {"status": "ok", "ssid": j["Device.WiFi.SSID.1.SSID"],
            "security": j["Device.WiFi.AccessPoint.1.Security.ModeEnabled"]}


def create_credential_reveal_grant(cpe_sn: str) -> dict:
    p = require_principal()
    # This only creates a short-lived UI challenge. Actual secret access is
    # re-authorized at redemption with a fresh step_up_age_s by the gateway.
    if not pdp().can_request_reveal(p, {"type": "cpe_device", "key": cpe_sn}).allowed:
        return NOT_AVAILABLE
    with connect("platform") as c:
        wo = c.execute("SELECT a.object FROM pdp_tuple a JOIN pdp_tuple s ON s.subject=a.object AND s.relation='serves'"
                       " JOIN pdp_tuple o ON o.subject=s.object AND o.relation='owns' AND o.object=?"
                       " WHERE a.subject=? AND a.relation='assignee'", (f"cpe_device:{cpe_sn}", p.key)).fetchone()
    work_order = wo[0].split(":", 1)[1] if wo else "BREAK-GLASS"
    ref = reveal.create_grant(p.user_id, cpe_sn, work_order, current_trace_id.get())
    telemetry.incr("reveal_grants_total{outcome=created}")
    return {"status": "step_up_required", "reveal_ref": ref, "expires_in": 60, "cpe_sn": cpe_sn}


def reboot_device(cpe_sn: str, confirm: bool = False) -> dict:
    if not confirm:
        return {"status": "needs_confirmation", "action": "reboot_device", "cpe_sn": cpe_sn}
    return {"status": "ok", **legacy.call("acs", "POST", f"/acs/v1/devices/{cpe_sn}/reboot").json()}


# ---------------- ticketing ----------------
def search_tickets(subscriber_id: str) -> dict:
    p = require_principal()
    if not check(p, "read_profile", "subscriber", subscriber_id, tool="search_tickets").allowed:
        return NOT_AVAILABLE
    tts = legacy.call("ticketing", "GET", legacy.BASE, params={"relatedEntity": subscriber_id}).json()
    for t in tts:  # ticket notes are untrusted free text
        t["note"] = [{"text": n["text"], "untrusted": True, "injection_flag": injection_score(n["text"]) >= 0.5}
                     for n in t["note"]]
    return {"status": "ok", "tickets": tts}


def create_ticket(subscriber_id: str, description: str, idempotency_key: str | None = None) -> dict:
    if not check(require_principal(), "read_profile", "subscriber", subscriber_id, tool="create_ticket").allowed:
        return NOT_AVAILABLE
    with connect("legacy") as c:
        if not c.execute("SELECT 1 FROM sub_mstr WHERE sbscr_id=?", (subscriber_id,)).fetchone():
            return NOT_AVAILABLE
    r = legacy.call("ticketing", "POST", legacy.BASE, json={"customer_id": subscriber_id, "description": description},
                    headers={"Idempotency-Key": idempotency_key or str(uuid.uuid4())})
    return {"status": "ok", "ticket": {"id": r.json()["id"]}}


def _ticket_if_allowed(ticket_id: str, tool: str) -> dict | None:
    r = legacy.call("ticketing", "GET", f"{legacy.BASE}/{ticket_id}")
    if r.status_code != 200:
        return None
    tt = r.json()
    sid = tt["relatedEntity"][0]["id"]
    return tt if check(require_principal(), "read_profile", "subscriber", sid, tool=tool).allowed else None


def get_ticket(ticket_id: str) -> dict:
    tt = _ticket_if_allowed(ticket_id, "get_ticket")
    if tt is None:
        return NOT_AVAILABLE
    tt["note"] = [{"text": n["text"], "untrusted": True, "injection_flag": injection_score(n["text"]) >= 0.5}
                  for n in tt["note"]]
    return {"status": "ok", "ticket": tt}


def add_note(ticket_id: str, text: str) -> dict:
    if _ticket_if_allowed(ticket_id, "add_note") is None:
        return NOT_AVAILABLE
    legacy.call("ticketing", "POST", f"{legacy.BASE}/{ticket_id}/note", json={"text": text[:1000]})
    return {"status": "ok", "ticket_id": ticket_id}


# ---------------- knowledge / topology / vendor ----------------
def allowed_doc_classes(p: Principal) -> set[str]:
    classes = set(CLASSIFICATION_LEVELS)
    allowed = set()
    for cls in classes:
        decision = pdp().check(p, "read", {"type": "document", "attributes": {"classification": cls}})
        if decision.reason_code == "POLICY_UNAVAILABLE":
            raise PolicyUnavailable()
        if decision.allowed:
            allowed.add(cls)
    return allowed


def search_procedures(query: str, device_model: str | None = None) -> dict:
    hits = rag.search(query, allowed_doc_classes(require_principal()), device_model)
    return {"status": "ok", "results": [
        {"citation": h["citation"], "title": h["title"], "revision": h["revision"], "superseded": h["superseded"],
         "ocr_confidence": h["ocr_confidence"], "content": h["parent"], "untrusted": True} for h in hits]}


def get_document_section(ref: str) -> dict:
    """ref format: DOC-ID#Section/pN (as returned in citations)."""
    doc_id, _, rest = ref.partition("#")
    section = rest.rsplit("/p", 1)[0]
    allowed = allowed_doc_classes(require_principal())
    ph = ",".join("?" * len(allowed)) or "''"
    with connect("platform") as c:
        r = c.execute(f"SELECT content, classification FROM kb_chunk WHERE doc_id=? AND section_path=? AND parent_id"
                      f" IS NULL AND quarantined=0 AND classification IN ({ph})", (doc_id, section, *allowed)).fetchone()
    return {"status": "ok", "ref": ref, "content": r[0], "untrusted": True} if r else NOT_AVAILABLE


def find_mop_for(model: str, symptom: str, firmware: str | None = None) -> dict:
    res = search_procedures(f"{symptom} procedure", device_model=model)
    if firmware:  # firmware_range like '3.0-3.9': keep docs whose major version matches
        major = firmware.split(".")[0]
        with connect("platform") as c:
            ok = {r[0] for r in c.execute("SELECT doc_id FROM kb_document WHERE firmware_range='*' OR"
                                         " firmware_range LIKE ?", (f"{major}.%",))}
        res["results"] = [h for h in res["results"] if h["citation"].split("#")[0] in ok]
    return res


def blast_radius(pon_port: str | None = None, subscriber_id: str | None = None) -> dict:
    port = pon_port or (kg.port_for_subscriber(subscriber_id) if subscriber_id else None)
    if not port:
        return NOT_AVAILABLE
    return {"status": "ok", **kg.blast_radius(port)}


def path_to_core(ont_id: str) -> dict:
    hops = kg.path_to_core(ont_id)
    return {"status": "ok", "hops": hops} if hops else NOT_AVAILABLE


def schedule_truck_roll(work_order_id: str, service_address: str, time_window: str, symptom: str) -> dict:
    p = require_principal()
    return a2a.schedule_truck_roll(p, {"work_order_id": work_order_id, "service_address": service_address,
                                       "time_window": time_window, "symptom": symptom})


TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("find_subscriber", find_subscriber, "read_profile", "subscriber", None, description="Resolve address/id"),
    Tool("get_work_orders", get_work_orders, "read_profile", "subscriber", "subscriber_id"),
    Tool("query_provisioning", query_provisioning, "read_profile", "subscriber", None, description="Text-to-SQL"),
    Tool("trigger_psk_reset", trigger_psk_reset, "trigger_psk_reset", "subscriber", "subscriber_id", False, True),
    Tool("get_device_status", get_device_status, "read_status", "cpe_device", "cpe_sn"),
    Tool("get_wifi_config", get_wifi_config, "read_config", "cpe_device", "cpe_sn"),
    Tool("create_credential_reveal_grant", create_credential_reveal_grant, "reveal_credential", "cpe_device", "cpe_sn",
         False),
    Tool("reboot_device", reboot_device, "reboot", "cpe_device", "cpe_sn", False, True),
    Tool("search_tickets", search_tickets, "read", "ticket", None),
    Tool("get_ticket", get_ticket, "read", "ticket", None),
    Tool("create_ticket", create_ticket, "create", "ticket", None, False),
    Tool("add_note", add_note, "add_note", "ticket", None, False),
    Tool("search_procedures", search_procedures, "read", "document", None),
    Tool("get_document_section", get_document_section, "read", "document", None),
    Tool("find_mop_for", find_mop_for, "read", "document", None),
    Tool("blast_radius", blast_radius, "read", "topology", None),
    Tool("path_to_core", path_to_core, "read", "topology", None),
    Tool("schedule_truck_roll", schedule_truck_roll, "share_with_vendor", "work_order", "work_order_id", False),
]}


def _scrub_obj(o):
    if isinstance(o, str):
        return scrub(o) if find_secrets(o) else o
    if isinstance(o, dict):
        return {k: _scrub_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_scrub_obj(v) for v in o]
    return o


def validate_state_write(result: dict) -> dict:
    """after_tool validator: nothing matching secret/canary detectors may enter LLM-visible state."""
    if find_secrets(json.dumps(result)):
        telemetry.incr("state_write_scrubbed_total")
        return _scrub_obj(result)
    return result


def call_tool(name: str, args: dict) -> dict:
    try:
        return _call_tool(name, args)
    except PolicyUnavailable:
        return {"status": "error", "reason_code": "POLICY_UNAVAILABLE", "retryable": False,
                "error": "The authorization service is unavailable. No protected data was accessed."}


def _call_tool(name: str, args: dict) -> dict:
    """before_tool (G2) -> tool -> after_tool validator. Also the MCP server entrypoint."""
    p = require_principal()
    tool = TOOLS.get(name)
    if tool is None:
        return {"status": "error", "reason_code": "UNKNOWN_TOOL", "error": "Unknown tool."}
    try:
        args = tool.args_model.model_validate(args).model_dump(exclude_none=True)
    except ValidationError:
        return {"status": "error", "reason_code": "INVALID_ARGUMENTS", "error": "Invalid tool input."}
    key = str(args.get(tool.key_arg, "*")) if tool.key_arg else "*"
    with telemetry.span(f"tool.{name}", **{"switchboard.policy.action": tool.action,
                                           "enduser.pseudo_id": telemetry.pseudo_id(p.user_id)}) as sp:
        if name == "create_credential_reveal_grant":
            # G2 for this tool is a non-secret preflight. The full Permit check
            # (including the fresh step-up attribute) runs only at redemption.
            d = pdp().can_request_reveal(p, {"type": tool.rtype, "key": key})
            decision = "allow" if d.allowed else "deny"
            audit.record(p.user_id, tool.action, f"{tool.rtype}:{key}", decision,
                         {"reason_code": d.reason_code, "tool": name}, current_trace_id.get())
            telemetry.incr(f"policy_decisions_total{{decision={decision}}}")
        else:
            d = check(p, tool.action, tool.rtype, key, tool=name)
        telemetry.set_attr(sp, "switchboard.policy.decision", "allow" if d.allowed else "deny")
        telemetry.set_attr(sp, "switchboard.policy.reason_code", d.reason_code)
        if not d.allowed:
            return _denied(d) if tool.rtype != "subscriber" or key == "*" else NOT_AVAILABLE
        if tool.destructive and confirmations.approved_action.get() != (name, args):
            return {"status": "needs_confirmation", "action": name, **args,
                    "confirmation_ref": confirmations.create(p.user_id, name, args)}
        try:
            result = tool.fn(**args, **({"confirm": True} if tool.destructive else {}))
        except PolicyUnavailable:
            raise
        except Exception as e:
            logging.getLogger(__name__).warning("tool_failure tool=%s type=%s", name, type(e).__name__)
            return {"status": "error", "reason_code": "UPSTREAM_UNAVAILABLE", "error": "The service is unavailable.",
                    "retryable": tool.read_only and isinstance(e, legacy.UpstreamError)}
        event("tool_completed", tool=name, status=result.get("status", "unknown"))
        return validate_state_write(result)
