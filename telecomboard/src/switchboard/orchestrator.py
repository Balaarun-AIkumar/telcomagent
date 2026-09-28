"""One bounded orchestrator: rewrite/route -> fixed tool plan -> execute -> grounded response.
Gemini optionally classifies intent; trusted Python owns plans and authorization."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from . import llm, memory, telemetry, text2sql, tools
from .context import Principal, current_principal, new_trace_id
from .core import connect, now
from .policy import ALTERNATIVES, MASK_PII_ROLES
from .redaction import find_secrets, injection_score, scan_output

PROMPTS = Path(__file__).parent / "data" / "prompts"
GLOSSARY = {r"\blos\b": "loss of signal", r"\bpsk\b": "wifi password", r"\bont\b": "optical network terminal",
            r"\bolt\b": "optical line terminal", r"\btruck roll\b": "technician dispatch", r"\bssid\b": "wifi network name"}
ADDRESS = re.compile(r"\b(\d{1,4}\s+[A-Z][a-z]+\s+(?:St|Ave|Rd|Dr|Ln|Way))\b")
COREF = re.compile(r"(?i)\b(same customer|that customer|this customer|same as yesterday|the customer)\b")
INTENTS = [
    ("psk_reset", r"(?i)\breset\b.*\b(wi-?fi|psk|password)\b"),
    ("wifi_password", r"(?i)(wi-?fi password|wifi key|\bpsk\b|password)"),
    ("outage", r"(?i)(no internet|outage|\blos\b|down\b|what'?s going on)"),
    ("fix_hold", r"(?i)(fix hold|still working|device status|status of)"),
    ("data_query", r"(?i)^(how many|list|which|count)\b"),
    ("procedure", r"(?i)(how (do|to)|procedure|mop|replace|pair)"),
]
ToolCategory = Literal["subscriber", "device", "knowledge", "ticket", "network", "field_vendor"]
SEVERITY = {"C": "critical", "M": "major", "N": "minor", "W": "warning"}


class RewrittenQuery(BaseModel):
    text: str
    original: str = ""
    intent: str
    address: str | None = None
    subscriber_id: str | None = None
    coref_from: str | None = None
    routing_source: str = "rules"


class Step(BaseModel):
    id: str
    category: ToolCategory
    tool: str
    inputs: dict[str, str | bool] = {}
    depends_on: list[str] = []


class Plan(BaseModel):
    steps: list[Step] = Field(max_length=6)
    requires_write: bool = False
    ux_sensitivity_hint: Literal["public", "internal", "restricted", "secret"] = "internal"


class Budget(BaseModel):
    max_iterations: int = 3
    max_tool_calls: int = 12
    deadline_s: float = 20.0


# ---------------- state (short-term memory) ----------------
def load_state(session_id: str, user_id: str) -> dict:
    with connect("platform") as c:
        r = c.execute("SELECT state FROM session_state WHERE session_id=? AND user_id=?", (f"{user_id}:{session_id}", user_id)).fetchone()
    return json.loads(r[0]) if r else {}


def save_state(session_id: str, user_id: str, state: dict) -> None:
    s = json.dumps(state)
    if find_secrets(s):
        raise ValueError("refusing to persist secret-like value into session state")
    with connect("platform") as c:
        c.execute("INSERT OR REPLACE INTO session_state VALUES (?,?,?,?)", (f"{user_id}:{session_id}", user_id, s, now()))


# ---------------- rewriter ----------------
def rewrite(message: str, state: dict, p: Principal) -> RewrittenQuery:
    text = message
    for pat, exp in GLOSSARY.items():
        text = re.sub(pat, lambda m, e=exp: f"{m.group(0)} ({e})", text, flags=re.IGNORECASE)
    intent = next((name for name, pat in INTENTS if re.search(pat, message)), "procedure")
    addr = ADDRESS.search(message)
    sid = re.search(r"\bS-\d{5}\b", message)
    rq = RewrittenQuery(text=text, original=message, intent=intent, address=addr.group(1) if addr else None,
                        subscriber_id=sid.group(0) if sid else None)
    routed = llm.route(message)
    if routed:
        rq.intent = routed
        rq.routing_source = "gemini"
    if not (rq.address or rq.subscriber_id) and COREF.search(message):
        subj = state.get("last_subject")
        if not subj and os.getenv("SB_LONG_TERM_MEMORY") == "1":
            mem = memory.recall(p, message, k=1)
            subj = mem[0]["subject_ref"] if mem else None
            rq.coref_from = "memory" if subj else None
        else:
            rq.coref_from = "session"
        if subj and subj.startswith("subscriber:"):
            rq.subscriber_id = subj.split(":", 1)[1]
    return rq


# ---------------- planner ----------------
def plan(rq: RewrittenQuery) -> Plan:
    find = Step(id="s1", category="subscriber", tool="find_subscriber",
                inputs={"address": rq.address} if rq.address else {"subscriber_id": rq.subscriber_id or ""})
    has_subject = bool(rq.address or rq.subscriber_id)
    i = rq.intent
    if i == "wifi_password" and has_subject:
        return Plan(ux_sensitivity_hint="secret", steps=[
            find, Step(id="s2", category="device", tool="create_credential_reveal_grant",
                       inputs={"cpe_sn": "$s1.cpe_sn"}, depends_on=["s1"]),
            Step(id="s3", category="knowledge", tool="search_procedures",
                 inputs={"query": "router will not pair WPS", "device_model": "$s1.model"}, depends_on=["s1"])])
    if i == "psk_reset" and has_subject:
        return Plan(requires_write=True, steps=[
            find, Step(id="s2", category="subscriber", tool="trigger_psk_reset",
                       inputs={"subscriber_id": "$s1.subscriber_id"}, depends_on=["s1"])])
    if i == "outage" and has_subject:
        return Plan(steps=[
            find,
            Step(id="s2", category="network", tool="blast_radius",
                 inputs={"subscriber_id": "$s1.subscriber_id"}, depends_on=["s1"]),
            Step(id="s3", category="device", tool="get_device_status",
                 inputs={"cpe_sn": "$s1.cpe_sn"}, depends_on=["s1"]),
            Step(id="s4", category="knowledge", tool="search_procedures",
                 inputs={"query": "PON port loss of signal outage procedure"})])
    if i == "fix_hold" and has_subject:
        return Plan(steps=[find, Step(id="s2", category="device", tool="get_device_status", inputs={"cpe_sn": "$s1.cpe_sn"},
                                      depends_on=["s1"]),
                           Step(id="s3", category="ticket", tool="search_tickets",
                                inputs={"subscriber_id": "$s1.subscriber_id"}, depends_on=["s1"])])
    if i == "data_query":
        return Plan(steps=[Step(id="s1", category="subscriber", tool="query_provisioning", inputs={"question": rq.text})])
    return Plan(steps=[Step(id="s1", category="knowledge", tool="search_procedures",
                            inputs={"query": rq.original or rq.text})])


# ---------------- plan executor + verifier (LoopAgent equivalent) ----------------
def _resolve(val, results: dict):
    if not isinstance(val, str) or not val.startswith("$"):
        return val
    sid, field = val[1:].split(".", 1)
    r = results.get(sid, {})
    if field == "work_order_id" and r.get("ticket"):
        return "WO-9" + r["ticket"]["id"].split("-")[1]  # incident work order mirrors the ticket
    subs = r.get("subscribers") or [{}]
    s, dev = subs[0], (subs[0].get("devices") or [{}])[0]
    return {"subscriber_id": s.get("subscriber_id"), "cpe_sn": dev.get("cpe_sn"), "model": dev.get("model"),
            "service_area": s.get("service_address") or f"zip {s.get('service_zip')}"}.get(field)


def _run_step(step: Step, results: dict, p: Principal) -> dict:
    if any(results.get(d, {}).get("status") not in ("ok", "step_up_required") for d in step.depends_on):
        return {"status": "blocked", "reason": "dependency not satisfied"}
    args = {k: _resolve(v, results) for k, v in step.inputs.items()}
    if any(v is None for v in args.values()) and step.tool != "search_procedures":
        return {"status": "blocked", "reason": "missing input"}
    args = {k: v for k, v in args.items() if v is not None}
    return tools.call_tool(step.tool, args)


async def execute(pl: Plan, results: dict, p: Principal, budget: Budget, counters: dict, only: set[str] | None = None):
    done = {k for k, v in results.items() if v.get("status") in ("ok", "step_up_required", "denied")}
    pending = [s for s in pl.steps if (only is None or s.id in only) and s.id not in done]
    while pending:
        ready = [s for s in pending if all(d in results for d in s.depends_on)]
        if not ready:
            break
        if (counters["tool_calls"] + len(ready) > budget.max_tool_calls
                or time.monotonic() >= counters["deadline"]):
            for s in ready:
                results[s.id] = {"status": "blocked", "reason": "budget"}
            break
        counters["tool_calls"] += len(ready)
        outs = await asyncio.gather(*(asyncio.to_thread(_run_step, s, results, p) for s in ready))
        for s, o in zip(ready, outs):
            results[s.id] = {**o, "evidence_id": f"E-{s.id}"}
        pending = [s for s in pending if s not in ready]


def verify(pl: Plan, results: dict) -> tuple[bool, set[str]]:
    """Every step must have produced evidence; retry only transient failures."""
    retry = {s.id for s in pl.steps if results.get(s.id, {}).get("retryable")}
    return not retry, retry


# ---------------- responder ----------------
def prompt_version(name: str) -> str:
    return hashlib.sha256((PROMPTS / f"{name}.txt").read_bytes()).hexdigest()[:12]


def refusal(alternatives: list[str]) -> str:
    tpl = (PROMPTS / "refusal.txt").read_text(encoding="utf-8").strip()
    return tpl.format(alternatives="; ".join(alternatives) or "open a ticket for an authorized team")


def describe_rows(question: str, rows: list[dict], limit: int = 10) -> str:
    """Turn query rows into a sentence or short list; the SQL itself is only shown in trace details."""
    if not rows:
        return "No matching records found in the data you can access."
    if len(rows) == 1 and len(rows[0]) == 1:
        value = next(iter(rows[0].values()))
        m = re.search(r"(?i)how many (.+?)\??$", question.strip())
        if m:
            phrase = re.sub(r"(?i)^(are there |do we have |is there )", "", m.group(1))
            return f"There {'is' if value == 1 else 'are'} {value} {phrase}."
        return f"The answer is {value}."
    label = lambda k: k.replace("_", " ")  # noqa: E731
    items = [", ".join(f"{label(k)} {v}" for k, v in row.items()) for row in rows[:limit]]
    more = f"\n...and {len(rows) - limit} more ({len(rows)} in total)." if len(rows) > limit else ""
    if len(rows) >= text2sql.MAX_LIMIT:
        more += f"\n(Results are capped at {text2sql.MAX_LIMIT} rows; ask a narrower question for the rest.)"
    count = f"at least {len(rows)}" if len(rows) >= text2sql.MAX_LIMIT else str(len(rows))
    return f"Found {count} result{'s' if len(rows) != 1 else ''}:\n- " + "\n- ".join(items) + more


def respond(rq: RewrittenQuery, pl: Plan, results: dict) -> tuple[str, list[dict], list[str]]:
    intents, cites = [], []
    if any(r.get("reason_code") == "POLICY_UNAVAILABLE" for r in results.values()):
        return ("The authorization service is unavailable, so I couldn't check access. "
                "Start Docker Desktop and the Permit PDP, then retry. "
                "This is a service outage, not a denial of your role."), intents, cites
    first = results.get("s1", {})
    alts = ALTERNATIVES["reveal_credential"] if rq.intent == "wifi_password" else first.get("safe_alternatives", [])
    if first.get("status") == "denied":
        return refusal(alts), intents, cites
    if rq.intent in ("wifi_password", "outage", "fix_hold", "psk_reset") and not (rq.address or rq.subscriber_id):
        return "Which subscriber or service address is this about?", intents, cites
    lines = []
    sub = (first.get("subscribers") or [{}])[0]
    cites = [r["results"][0]["citation"] for r in results.values() if r.get("results")]
    if rq.intent == "wifi_password":
        g = results.get("s2", {})
        if g.get("status") != "step_up_required":
            return refusal(ALTERNATIVES["reveal_credential"]), intents, cites
        intents.append({"type": "step_up_reveal", "reveal_ref": g["reveal_ref"], "expires_in": g["expires_in"],
                        "cpe_sn": g["cpe_sn"]})
        lines.append(f"Confirm the on-site reveal card to view the Wi-Fi password for {g['cpe_sn']} "
                     f"({sub.get('subscriber_id')}). It is shown in the app only and expires in {g['expires_in']}s.")
        kb = results.get("s3", {}).get("results", [])
        if kb:
            lines.append(f"If pairing still fails: {kb[0]['content'].splitlines()[0]} [{kb[0]['citation']}]")
    elif rq.intent == "psk_reset":
        r = results.get("s2", {})
        if r.get("status") == "needs_confirmation":
            intents.append({"type": "confirm_action", "action": "trigger_psk_reset", "subscriber_id": r["subscriber_id"],
                            "confirmation_ref": r["confirmation_ref"]})
            lines.append("Please confirm: send a Wi-Fi password reset to the account holder's number on file.")
        elif r.get("status") == "ok":
            lines.append("Done. A new Wi-Fi password was sent to the account holder's number on file.")
        else:
            return refusal(r.get("safe_alternatives", [])), intents, cites
    elif rq.intent == "outage":
        n = results.get("s2", {})
        if n.get("pon_port"):
            alarms = ", ".join(f"{a['code']} ({SEVERITY.get(a['sev'], a['sev'])}) on {a['obj_ref']}"
                               for a in n.get("alarms", [])) or "none"
            cause = "loss of optical signal; check the documented procedure" if n.get("alarms") else "no active alarm found yet"
            lines.append(f"Blast radius: {n['pon_port']} on {n.get('olt')} with {n.get('affected_count')} subscribers "
                         f"affected. Active alarms: {alarms}. Likely cause: {cause}.")
        d = results.get("s3", {})
        if d.get("status") == "ok":
            lines.append(f"{d['cpe_sn']} optical status: {d['optical']} (rx {d['rx_power_dbm']} dBm).")
        kb = results.get("s4", {}).get("results", [])
        if kb:
            lines.append(f"Procedure: {kb[0]['title']} [{kb[0]['citation']}]")
    elif rq.intent == "fix_hold":
        d, t = results.get("s2", {}), results.get("s3", {})
        if d.get("status") != "ok":
            return refusal(d.get("safe_alternatives", [])), intents, cites
        lines.append(f"{d['cpe_sn']} ({sub.get('subscriber_id')}) is {d['optical']} on firmware {d['firmware']}, "
                     f"rx {d['rx_power_dbm']} dBm.")
        opened = [x["id"] for x in t.get("tickets", []) if x["status"] == "open"]
        lines.append(f"Open tickets: {', '.join(opened) or 'none'}.")
    elif rq.intent == "data_query":
        r = first
        if r.get("status") != "ok":
            return ("I couldn't answer that from provisioning data. Try asking for counts or lists of customers, "
                    "devices or work orders, e.g. 'How many active customers in 02139?'"), intents, cites
        lines.append(describe_rows(rq.original or rq.text, r["rows"]))
    else:
        kb = first.get("results", [])
        if not kb:
            return "I couldn't find a documented procedure for that.", intents, cites
        top = kb[0]
        doc = top["citation"].split("#")[0]
        same = sorted((h for h in kb if h["citation"].startswith(doc + "#")),
                      key=lambda h: int(h["citation"].rsplit("/p", 1)[1]))
        lines.append(f"{top['title']} (rev {top['revision']}) [{doc}]")
        for h in same:
            section = h["citation"].split("#")[1].rsplit("/p", 1)[0]
            lines.append(f"{section}: {' '.join(h['content'].splitlines())} [{h['citation']}]")
        if any(h["superseded"] for h in kb):
            lines.append("Note: an older, superseded revision also matched; follow the latest revision.")
        if top.get("ocr_confidence", 1) < 0.8:
            lines.append("Caution: source is a scanned document with low OCR confidence.")
    return "\n".join(lines), intents, cites


# ---------------- entrypoint ----------------
async def arun(message: str, p: Principal, session_id: str = "default", budget: Budget | None = None) -> dict:
    budget = budget or Budget()
    tok = current_principal.set(p)
    subj_tok = tools.authorized_subjects.set(set())
    trace_id = new_trace_id()
    t0 = time.monotonic()
    try:
        with telemetry.span("orchestrator.run", **{"switchboard.persona.role": p.role,
                                                   "enduser.pseudo_id": telemetry.pseudo_id(p.user_id),
                                                   "switchboard.prompt.refusal_version": prompt_version("refusal")}) as root:
            root["input"] = telemetry._clean(message[:500])  # local debug buffer only
            trace_id = root["trace_id"]
            if injection_score(message) >= 0.5:  # G1 input guard
                telemetry.set_attr(root, "switchboard.guard.input", "blocked")
                return {"text": refusal(["Ask about a specific device, subscriber or procedure"]), "ui_intents": [],
                        "trace_id": trace_id, "blocked": "input_guard"}
            state = load_state(session_id, p.user_id)
            rq = rewrite(message, state, p)
            pl = plan(rq)
            telemetry.set_attr(root, "switchboard.plan.step_count", len(pl.steps))
            results: dict = {}
            counters = {"tool_calls": 0, "deadline": t0 + budget.deadline_s}
            only, last_hash = None, None
            for it in range(1, budget.max_iterations + 1):
                telemetry.set_attr(root, "switchboard.loop.iteration", it)
                await execute(pl, results, p, budget, counters, only)
                ok, retry = verify(pl, results)
                h = hashlib.sha256(json.dumps({k: v.get("status") for k, v in results.items()}).encode()).hexdigest()
                if ok or h == last_hash or time.monotonic() - t0 > budget.deadline_s:
                    break
                last_hash, only = h, retry
                only = retry | {s.id for s in pl.steps if results.get(s.id, {}).get("status") == "blocked"}
                for r in only:
                    results.pop(r, None)
            text, intents, cites = respond(rq, pl, results)
            text, findings = scan_output(text, mask=p.role in MASK_PII_ROLES,
                                         authorized_subjects=tools.authorized_subjects.get() or set())
            telemetry.set_attr(root, "switchboard.guard.output_findings", ",".join(findings) or "none")
            sub = (results.get("s1", {}).get("subscribers") or [{}])[0].get("subscriber_id")
            if sub:
                state["last_subject"] = f"subscriber:{sub}"
                if os.getenv("SB_LONG_TERM_MEMORY") == "1":
                    memory.store_episode(p, f"subscriber:{sub}", f"{rq.intent} for subscriber:{sub}; "
                                     f"outcome: {'; '.join(r.get('status', '') for r in results.values())}")
            state.setdefault("turns", []).append({"intent": rq.intent, "trace_id": trace_id})
            state["turns"] = state["turns"][-20:]
            save_state(session_id, p.user_id, state)
            return {"text": text, "ui_intents": intents, "citations": cites, "trace_id": trace_id,
                    "intent": rq.intent, "routing_source": rq.routing_source, "coref_from": rq.coref_from, "sql": results.get("s1", {}).get("sql"),
                    "plan": [s.model_dump() for s in pl.steps],
                    "steps": {k: {"status": v.get("status"), "reason_code": v.get("reason_code")}
                              for k, v in results.items()}}
    finally:
        tools.authorized_subjects.reset(subj_tok)
        current_principal.reset(tok)


def run(message: str, p: Principal, session_id: str = "default", budget: Budget | None = None) -> dict:
    return asyncio.run(arun(message, p, session_id, budget))
