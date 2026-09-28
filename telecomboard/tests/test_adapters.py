"""Adapters (MCP, ADK), extra tools, UI/dev endpoints, and validator fuzzing."""
import asyncio
import json

import pytest
from conftest import principal, token
from hypothesis import given, settings
from hypothesis import strategies as st

from switchboard import tools
from switchboard.context import current_principal
from switchboard.text2sql import SQLRejected, validate


def as_user(user, fn, *a, **kw):
    t = current_principal.set(principal(user))
    s = tools.authorized_subjects.set(set())
    try:
        return fn(*a, **kw)
    finally:
        tools.authorized_subjects.reset(s)
        current_principal.reset(t)


def test_new_tools_respect_policy():
    assert as_user("maya", tools.call_tool, "get_ticket", {"ticket_id": "TT-5001"})["status"] == "ok"
    assert as_user("ext-t1", tools.call_tool, "get_ticket", {"ticket_id": "TT-5001"})["status"] == "denied"
    assert as_user("maya", tools.call_tool, "add_note", {"ticket_id": "TT-5001", "text": "on site"})["status"] == "ok"
    assert as_user("priya", tools.call_tool, "path_to_core", {"ont_id": "ONT-00000"})["hops"][1] == "PON-01-01"
    assert as_user("maya", tools.call_tool, "path_to_core", {"ont_id": "ONT-00000"})["status"] == "denied"
    mop = as_user("maya", tools.call_tool, "find_mop_for", {"model": "HGW-2400", "symptom": "ONT replacement",
                                                            "firmware": "3.1.2"})
    assert all("ONT-r1" not in r["citation"] for r in mop["results"])  # r1 covers firmware 2.x only
    sec = as_user("maya", tools.call_tool, "get_document_section", {"ref": "DOC-MOP-ONT-r2#Rollback/p3"})
    assert sec["status"] == "ok" and "old ONT" in sec["content"]
    assert as_user("maya", tools.call_tool, "get_document_section",
                   {"ref": "DOC-MOP-OLT-r1#Procedure/p2"})["status"] == "denied"  # restricted doc


def test_mcp_servers_expose_annotated_tools_and_require_auth():
    pytest.importorskip("mcp")
    from switchboard.mcp_servers import SERVERS, build

    for name, expected in SERVERS.items():
        listed = {t.name: t for t in asyncio.run(build(name).list_tools())}
        assert set(listed) == set(expected)
    acs = {t.name: t for t in asyncio.run(build("acs").list_tools())}
    assert acs["reboot_device"].annotations.destructiveHint and acs["get_device_status"].annotations.readOnlyHint
    out = asyncio.run(build("acs").call_tool("get_device_status", {"args": {"cpe_sn": "CPE-5521"}}))
    assert "UNAUTHENTICATED" in json.dumps(out, default=str)


def test_every_adk_llm_agent_has_guardrail_callbacks():
    pytest.importorskip("google.adk")
    from google.adk.agents import LlmAgent

    from switchboard import adk_app

    def walk(a):
        yield a
        for s in getattr(a, "sub_agents", []) or []:
            yield from walk(s)

    agents = [a for a in walk(adk_app.build_root()) if isinstance(a, LlmAgent)]
    assert agents and all(a.before_model_callback is adk_app.before_model and
                          a.after_model_callback is adk_app.after_model for a in agents)


def test_ui_and_dev_endpoints(gw, monkeypatch):
    assert "Switchboard" in gw.get("/").text
    assert {u["user_id"] for u in gw.get("/dev/users").json()} >= {"maya", "ext-t1", "priya"}
    assert gw.post("/dev/work-orders/WO-1042/IN_PROGRESS").status_code == 200
    obs = gw.get("/dev/observability").json()
    assert obs["audit_chain_intact"] is True
    monkeypatch.setenv("SB_DEV_ENDPOINTS", "0")
    assert gw.post("/dev/token", json={"user_id": "maya"}).status_code == 404


def test_rate_limit(gw, monkeypatch):
    from switchboard import gateway

    monkeypatch.setattr(gateway, "RATE", 2)
    h = token(gw, "maya")
    codes = [gw.post("/v1/chat", json={"message": "How do I pair WPS?"}, headers=h).status_code for _ in range(3)]
    assert codes[-1] == 429


SQLISH = st.lists(st.sampled_from(["SELECT", "customer_id", "name", "FROM", "canon_customer", "legacy.wln_cfg",
                                   "psk_enc", "WHERE", "=", "'x'", ",", "*", ";", "DROP", "UNION", "(", ")",
                                   "load_extension", "LIMIT", "999999", "sub_mstr", "status"]), max_size=14)


@settings(max_examples=300, deadline=None)
@given(SQLISH)
def test_validator_fuzz_never_allows_forbidden(tokens):
    sql = " ".join(tokens)
    try:
        out = validate(sql)
    except SQLRejected:
        return
    low = out.lower()
    assert not any(bad in low for bad in ("psk_enc", "wln_cfg", "sub_mstr", "load_extension", "drop", " name"))
    assert "limit" in low


@pytest.mark.parametrize("user", ["maya", "priya"])
def test_budget_caps_tool_calls(user):
    from switchboard import orchestrator

    r = orchestrator.run("Subscribers report no internet at 14 Elm St.", principal(user),
                         budget=orchestrator.Budget(max_tool_calls=1))
    assert any(s.get("status") == "blocked" for s in r["steps"].values())
