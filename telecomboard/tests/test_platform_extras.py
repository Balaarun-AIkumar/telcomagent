"""A2A contract + streaming, one-trace propagation, chaos/circuit breaker, cassettes, memory TTL,
generated policy invariants, trace2test and variance tooling."""
import json
from itertools import product
from pathlib import Path

import pytest
from conftest import principal, token

from switchboard import a2a, auth, debugtools, legacy, memory, telemetry, tools
from switchboard.context import current_principal
from switchboard.core import advance_clock
from switchboard.policy import pdp

OUTAGE = "Subscribers report no internet at 14 Elm St. What's going on?"
WIFI = "Router won't pair at 14 Elm St. What's the Wi-Fi password?"


def _rpc(client, method, params, aud=a2a.VENDOR_AUD):
    return client.post("/", json={"jsonrpc": "2.0", "id": 7, "method": method, "params": params},
                       headers={"Authorization": f"Bearer {auth.issue('priya', audience=aud, scope='schedule_truck_roll' if aud == a2a.VENDOR_AUD else 'outage_triage')}"})


def test_a2a_contract_send_get_cancel_stream():
    from fastapi.testclient import TestClient

    c = TestClient(a2a.vendor_app)
    card = c.get("/.well-known/agent-card.json").json()
    assert {"name", "url", "version", "capabilities", "skills", "securitySchemes"} <= set(card)
    assert card["capabilities"]["streaming"] is True
    msg = {"message": {"role": "user", "messageId": "m1", "parts": [
        {"kind": "data", "data": {"work_order_id": "WO-95001", "time_window": "today"}}]}}
    task = _rpc(c, "message/send", msg).json()["result"]
    assert task["status"]["state"] == "completed" and task["artifacts"][0]["parts"][0]["data"]["job_id"].startswith("JOB-")
    assert _rpc(c, "tasks/get", {"id": task["id"]}).json()["result"]["id"] == task["id"]
    assert _rpc(c, "tasks/cancel", {"id": task["id"]}).json()["result"]["status"]["state"] == "canceled"
    assert _rpc(c, "tasks/get", {"id": "nope"}).json()["error"]["code"] == -32001
    assert _rpc(c, "bogus/method", {}).json()["error"]["code"] == -32601
    with c.stream("POST", "/", json={"jsonrpc": "2.0", "id": 8, "method": "message/stream", "params": msg},
                  headers={"Authorization": f"Bearer {auth.issue('priya', audience=a2a.VENDOR_AUD, scope='schedule_truck_roll')}"}) as r:
        events = [json.loads(line[6:])["result"] for line in r.iter_lines() if line.startswith("data: ")]
    assert [e["kind"] for e in events] == ["status-update", "artifact-update", "status-update"]
    assert events[-1]["final"] and events[-1]["status"]["state"] == "completed"


def test_s5_is_one_trace_across_services(gw):
    r = gw.post("/v1/chat", json={"message": OUTAGE}, headers=token(gw, "priya")).json()
    names = {s["name"] for s in telemetry.SPAN_LOG if s["trace_id"] == r["trace_id"]}
    assert {"orchestrator.run", "tool.get_device_status", "tool.blast_radius", "legacy.acs-lite"} <= names
    root = next(s for s in telemetry.SPAN_LOG if s["trace_id"] == r["trace_id"] and s["name"] == "orchestrator.run")
    assert len(root["attrs"]["switchboard.prompt.refusal_version"]) == 12


def test_chaos_retries_then_circuit_opens(monkeypatch):
    monkeypatch.setenv("SB_CHAOS_5XX", "1")
    t = current_principal.set(principal("priya"))
    s = tools.authorized_subjects.set(set())
    try:
        outs = [tools.call_tool("get_device_status", {"cpe_sn": "CPE-5521"}) for _ in range(6)]
    finally:
        tools.authorized_subjects.reset(s)
        current_principal.reset(t)
        legacy._breaker.clear()
    assert all(o["status"] == "error" and o["retryable"] for o in outs)
    assert outs[-1]["reason_code"] == "UPSTREAM_UNAVAILABLE"


def test_cassette_replay_isolates_environment(tmp_path, monkeypatch):
    tape = tmp_path / "s5.json"
    monkeypatch.setenv("SB_CASSETTE", str(tape))
    monkeypatch.setenv("SB_CASSETTE_MODE", "record")
    from switchboard import orchestrator

    live = orchestrator.run(OUTAGE, principal("priya"), session_id="rec")
    assert tape.exists() and json.loads(tape.read_text())
    monkeypatch.setenv("SB_CASSETTE_MODE", "replay")
    monkeypatch.setenv("SB_CHAOS_5XX", "1")  # live upstreams would now fail
    replayed = orchestrator.run(OUTAGE, principal("priya"), session_id="rep")
    legacy._breaker.clear()
    assert replayed["steps"]["s3"]["status"] == live["steps"]["s3"]["status"] == "ok"


def test_memory_ttl_retention():
    memory.store_episode(principal("maya"), "subscriber:S-88123", "ttl probe", ttl_days=1)
    advance_clock(2 * 86400)
    try:
        assert memory.purge_expired() >= 1
    finally:
        advance_clock(-2 * 86400)


USERS = ["maya", "raj", "ext-t1", "priya", "sam", "dana", "lee", "tech-off"]
RESOURCES = [("subscriber", "S-88123"), ("subscriber", "S-77001"), ("cpe_device", "CPE-5521"),
             ("cpe_device", "CPE-4410"), ("work_order", "WO-1042"), ("work_order", "WO-3001")]
ACTIONS = ["read_profile", "read_pii", "trigger_psk_reset", "read_status", "read_config", "reveal_credential",
           "reboot", "read", "update", "share_with_vendor"]


def test_generated_policy_invariants():
    """480 generated persona x action x resource checks against invariants (not a copy of the rules)."""
    ps = {u: principal(u) for u in USERS}
    allowed = {(u, a, r, k) for u, a, (r, k) in product(USERS, ACTIONS, RESOURCES)
               if pdp().check(ps[u], a, {"type": r, "key": k},
                              {"step_up_age_s": 1} if a == "reveal_credential" else None).allowed}
    reveals = {(u, k) for u, a, r, k in allowed if a == "reveal_credential"}
    bg = {(u, k) for u in ("dana", "lee") for _, k in RESOURCES if pdp().break_glass(u, "cpe_device", k)}
    assert reveals == {("maya", "CPE-5521"), ("sam", "CPE-4410")} | bg
    assert not any(u == "ext-t1" for u, *_ in allowed)                        # least privilege queue
    assert not any(a == "read_pii" and u in ("sam", "priya", "ext-t1") for u, a, *_ in allowed)
    assert not any(u == "tech-off" and a == "reveal_credential" for u, a, *_ in allowed)
    assert not any(u == "maya" and k in ("S-77001", "CPE-4410", "WO-3001") for u, _, _, k in allowed)
    assert not any(u == "sam" and k in ("S-88123", "CPE-5521", "WO-1042") for u, _, _, k in allowed)
    assert ("raj", "trigger_psk_reset", "subscriber", "S-88123") in allowed


def test_trace2test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SB_TRACE_FIXTURES", str(tmp_path))
    from switchboard import orchestrator

    r = orchestrator.run(WIFI, principal("ext-t1"))
    fx = json.loads(debugtools.export(r["trace_id"], "probe").read_text())
    assert fx["user"] == "ext-t1" and fx["expected_decisions"]
    assert debugtools.replay(fx) == []
    fx["expected_tools"].append("tool.reveal_everything")
    assert debugtools.replay(fx)  # a changed trajectory is reported


@pytest.mark.parametrize("path", sorted((Path(__file__).parents[1] / "evals" / "datasets" / "traces").glob("*.json")),
                         ids=lambda p: p.stem)
def test_recorded_trace_goldens_still_pass(path):
    assert debugtools.replay(json.loads(path.read_text())) == []


def test_variance_pass_k():
    rep = debugtools.variance([("maya", WIFI), ("ext-t1", WIFI), ("priya", OUTAGE)], k=2)
    assert all(v["pass_k"] for v in rep.values()), rep
