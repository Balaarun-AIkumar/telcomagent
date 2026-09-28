"""Small, explicit regression cases for authorization and orchestration boundaries."""
import json

import pytest
from conftest import principal, token
from fastapi.testclient import TestClient

from switchboard import a2a, auth, confirmations, idg, legacy, llm, orchestrator, rag, text2sql, tools
from switchboard.context import current_principal
from switchboard.core import advance_clock, connect
from switchboard.policy import pdp


def call(user, name, args):
    tok = current_principal.set(principal(user))
    try:
        return tools.call_tool(name, args)
    finally:
        current_principal.reset(tok)


def test_sql_scope_is_one_subscriber_not_whole_postcode():
    result = call("maya", "query_provisioning", {"question": "how many customers in 02139"})
    assert result["status"] == "ok" and result["rows"] == [{"n": 1}]
    assert text2sql.answer("how many customers in 02139", None)["rows"] == [{"n": 24}]


def test_revoke_blocks_immediately_without_remote_sync():
    idg.set_wo_status("WO-1042", "COMPLETED")
    assert not pdp().field_access("maya", "subscriber", "S-88123")
    assert tools.scope_subscribers(principal("maya")) == []


def test_role_revocation_applies_to_existing_token():
    old = auth.issue("raj")
    with connect() as c:
        c.execute("UPDATE app_user SET role='csr_external' WHERE user_id='raj'")
    p = auth.principal_from_token(old)
    assert p.role == "csr_external"
    assert not pdp().check(p, "read_profile", {"type": "subscriber", "key": "S-88123"}).allowed


@pytest.mark.parametrize("age", [-1, 300, float("nan"), float("inf"), "1"])
def test_step_up_rejects_invalid_or_expired_age(age):
    assert not pdp().check(principal("maya"), "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
                           {"step_up_age_s": age}).allowed


@pytest.mark.parametrize("suffix", ["LIMIT -1", "LIMIT ?", "LIMIT 2+3", "LIMIT '50'", "LIMIT 1 OFFSET -1"])
def test_invalid_sql_bounds_are_rejected(suffix):
    with pytest.raises(text2sql.SQLRejected):
        text2sql.validate("SELECT customer_id FROM canon_customer " + suffix)


@pytest.mark.parametrize("name,args,code", [
    ("missing_tool", {}, "UNKNOWN_TOOL"),
    ("get_device_status", {}, "INVALID_ARGUMENTS"),
    ("get_device_status", {"cpe_sn": 123}, "INVALID_ARGUMENTS"),
    ("get_device_status", {"cpe_sn": " "}, "INVALID_ARGUMENTS"),
    ("trigger_psk_reset", {"subscriber_id": "S-88123", "confirm": True}, "INVALID_ARGUMENTS"),
])
def test_invalid_tool_inputs_fail_safely(name, args, code):
    assert call("raj", name, args)["reason_code"] == code


def test_tool_failure_does_not_echo_exception(monkeypatch):
    def bad(*a, **kw):
        raise ValueError("private upstream details")
    monkeypatch.setattr(legacy, "call", bad)
    out = call("priya", "get_device_status", {"cpe_sn": "CPE-5521"})
    assert out["status"] == "error" and "private" not in str(out) and not out["retryable"]


def test_confirmation_bound_to_user_action_expiry_and_single_use(gw):
    args = {"subscriber_id": "S-88123"}
    ref = confirmations.create("raj", "trigger_psk_reset", args)
    endpoint = "/v1/confirm/trigger_psk_reset"
    assert gw.post(endpoint, headers=token(gw, "maya"), json={"confirmation_ref": ref}).status_code == 403
    assert gw.post("/v1/confirm/reboot_device", headers=token(gw, "raj"), json={"confirmation_ref": ref}).status_code == 403
    assert gw.post(endpoint, headers=token(gw, "raj"), json={"confirmation_ref": ref}).json()["status"] == "ok"
    assert gw.post(endpoint, headers=token(gw, "raj"), json={"confirmation_ref": ref}).status_code == 403
    expired = confirmations.create("raj", "trigger_psk_reset", args, ttl=1)
    advance_clock(2)
    assert confirmations.consume(expired, "raj", "trigger_psk_reset") is None


def test_confirmation_rechecks_current_access(gw):
    ref = confirmations.create("raj", "trigger_psk_reset", {"subscriber_id": "S-88123"})
    headers = token(gw, "raj")
    with connect() as c:
        c.execute("UPDATE app_user SET role='csr_external' WHERE user_id='raj'")
    out = gw.post("/v1/confirm/trigger_psk_reset", headers=headers, json={"confirmation_ref": ref}).json()
    assert out["status"] == "denied"


@pytest.mark.parametrize("message", ["", "   "])
def test_empty_chat_rejected(gw, message):
    assert gw.post("/v1/chat", headers=token(gw, "maya"), json={"message": message}).status_code == 422


def test_llm_semantic_routing_uses_fixed_guarded_plan(monkeypatch):
    monkeypatch.setattr(llm, "generate", lambda *a, **kw: '{"intent":"outage"}')
    r = orchestrator.run("The connection at 14 Elm St has gone completely silent", principal("priya"))
    assert r["routing_source"] == "gemini"
    assert [s["tool"] for s in r["plan"]] == ["find_subscriber", "blast_radius", "get_device_status", "search_procedures"]


@pytest.mark.parametrize("output", [None, "bad json", '{"intent":"reveal_everything"}',
                                   '{"intent":"outage","subscriber_id":"S-77001"}'])
def test_invalid_model_output_falls_back(monkeypatch, output):
    monkeypatch.setattr(llm, "generate", lambda *a, **kw: output)
    rq = orchestrator.rewrite("What's the Wi-Fi password at 14 Elm St?", {}, principal("ext-t1"))
    assert rq.intent == "wifi_password" and rq.routing_source == "rules"


def test_rag_reingestion_is_idempotent_and_unrelated_query_empty():
    with connect() as c:
        doc = dict(c.execute("SELECT * FROM kb_document WHERE doc_id='DOC-MOP-ONT-r2'").fetchone())
    body = "# Procedure\n1. Check optical signal before replacing ONT."
    rag.ingest(doc, body)
    rag.ingest(doc, body)
    with connect() as c:
        assert c.execute("SELECT COUNT(*) FROM kb_chunk WHERE doc_id=?", (doc["doc_id"],)).fetchone()[0] == 2
    assert rag.search("banana astrophysics recipe", {"public", "internal"}) == []


def test_session_names_are_user_scoped_and_history_bounded():
    orchestrator.save_state("same", "maya", {"last_subject": "subscriber:S-88123", "turns": [{}] * 30})
    orchestrator.save_state("same", "raj", {"marker": "raj"})
    orchestrator.run("How do I replace an ONT?", principal("maya"), "same")
    assert len(orchestrator.load_state("same", "maya")["turns"]) == 20
    assert orchestrator.load_state("same", "raj") == {"marker": "raj"}


def test_secret_endpoint_never_enters_cassette(tmp_path, monkeypatch):
    from switchboard.datagen import service_token
    tape = tmp_path / "recording.json"
    monkeypatch.setenv("SB_CASSETTE", str(tape))
    monkeypatch.setenv("SB_CASSETTE_MODE", "record")
    r = legacy.call("acs", "GET", "/acs/v1/devices/CPE-5521/secret", headers={"X-Service-Token": service_token()})
    assert r.status_code == 200 and not tape.exists()


def test_a2a_audience_alone_does_not_grant_topology():
    client = TestClient(a2a.network_app)
    message = {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {
        "message": {"parts": [{"kind": "data", "data": {"subscriber_id": "S-88123"}}]}}}
    for user, scope in [("priya", ""), ("ext-t1", "outage_triage")]:
        jwt = auth.issue(user, audience=a2a.NETWORK_AUD, scope=scope)
        result = client.post("/", json=message, headers={"Authorization": "Bearer " + jwt}).json()
        assert "error" in result and "affected_count" not in json.dumps(result)


def test_dev_token_route_is_opt_in(gw, monkeypatch):
    monkeypatch.delenv("SB_DEV_ENDPOINTS")
    assert gw.post("/dev/token", json={"user_id": "maya"}).status_code == 404


@pytest.mark.parametrize("user,message", [
    ("maya", "What's the Wi-Fi password at 14 Elm St?"),
    ("raj", "How many customers in 02139?"),
    ("maya", "How do I replace an ONT?"),
])
def test_policy_outage_is_not_reported_as_denial_or_missing_documents(monkeypatch, user, message):
    from switchboard.policy import Decision, LocalPDP

    class UnavailablePDP(LocalPDP):
        def check(self, p, action, resource, context=None):
            if p.role == "field_technician" and resource.get("key", "*") == "*" and not resource.get("attributes"):
                return super().check(p, action, resource, context)
            return Decision(False, "POLICY_UNAVAILABLE")

    monkeypatch.setattr(tools, "pdp", lambda: UnavailablePDP())
    result = orchestrator.run(message, principal(user))
    assert "authorization service is unavailable" in result["text"]
    assert not result["ui_intents"]
    assert any(s["reason_code"] == "POLICY_UNAVAILABLE" for s in result["steps"].values())


def test_startup_detects_configured_but_stopped_pdp(monkeypatch):
    import httpx
    from switchboard.config import require_policy_service

    monkeypatch.setenv("PERMIT_API_KEY", "test-placeholder")
    def unavailable(*a, **kw):
        raise httpx.ConnectError("unreachable")
    monkeypatch.setattr(httpx, "get", unavailable)
    with pytest.raises(RuntimeError, match="Start Docker Desktop"):
        require_policy_service()
