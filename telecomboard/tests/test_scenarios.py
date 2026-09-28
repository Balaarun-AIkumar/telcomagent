"""End-to-end golden scenarios through the gateway (S1-S6) + break-glass + HITL."""
import json

import pytest
from conftest import all_psks, token
from switchboard import audit, idg

WIFI = "Router won't pair at 14 Elm St. What's the Wi-Fi password?"


def chat(gw, user, msg, session="t"):
    r = gw.post("/v1/chat", json={"message": msg, "session_id": session}, headers=token(gw, user))
    assert r.status_code == 200, r.text
    return r.json()


def test_s1_allowed_reveal_is_ui_only_and_single_use(gw):
    r = chat(gw, "maya", WIFI)
    intent = next(i for i in r["ui_intents"] if i["type"] == "step_up_reveal")
    assert not any(p in str(r) for p in all_psks())
    rv = gw.post(f"/v1/reveal/{intent['reveal_ref']}", headers=token(gw, "maya"))
    assert rv.status_code == 200 and rv.json()["psk"] in all_psks()
    assert rv.headers["cache-control"] == "no-store"
    assert gw.post(f"/v1/reveal/{intent['reveal_ref']}", headers=token(gw, "maya")).status_code == 403


def test_reveal_ref_bound_to_grantee(gw):
    ref = next(i for i in chat(gw, "maya", WIFI)["ui_intents"])["reveal_ref"]
    assert gw.post(f"/v1/reveal/{ref}", headers=token(gw, "raj")).status_code == 403


def test_s2_refusal_identical_for_existing_and_missing_subscriber(gw):
    a = chat(gw, "ext-t1", WIFI)
    b = chat(gw, "ext-t1", "Router won't pair at 99 Nowhere St. What's the Wi-Fi password?")
    assert a["text"] == b["text"] and "password reset" in a["text"].lower()
    assert "S-88123" not in a["text"] and not a["ui_intents"]


def test_csr_gets_safe_alternative_then_reset(gw):
    r = chat(gw, "raj", WIFI)
    assert not r["ui_intents"] and "reset" in r["text"].lower()
    r = chat(gw, "raj", "Reset the Wi-Fi password for S-88123")
    assert r["ui_intents"][0]["type"] == "confirm_action"
    r = chat(gw, "raj", "Reset the Wi-Fi password for S-88123, confirmed")
    assert r["ui_intents"][0]["type"] == "confirm_action"
    r = gw.post("/v1/confirm/trigger_psk_reset", headers=token(gw, "raj"),
                json={"confirmation_ref": r["ui_intents"][0]["confirmation_ref"]}).json()
    assert "Done" in r["text"]


def test_s3_denied_after_work_order_closed(gw):
    idg.set_wo_status("WO-1042", "COMPLETED")
    idg.sync_once()
    try:
        r = chat(gw, "maya", WIFI)
        assert not r["ui_intents"] and "can't complete" in r["text"]
    finally:
        idg.set_wo_status("WO-1042", "IN_PROGRESS")
        idg.sync_once()


def test_s5_outage_read_only(gw):
    r = chat(gw, "priya", "Subscribers report no internet at 14 Elm St. What's going on?")
    assert "PON-01-01" in r["text"] and "JOB-" not in r["text"] and "TT-" not in r["text"]
    assert all(s["status"] == "ok" for s in r["steps"].values()), r["steps"]


def test_s6_memory_with_read_time_reauth(gw, monkeypatch):
    monkeypatch.setenv("SB_LONG_TERM_MEMORY", "1")
    chat(gw, "maya", WIFI, session="day1")
    r = chat(gw, "maya", "Same customer as yesterday. Did the fix hold?", session="day2")
    assert r["coref_from"] == "memory" and "CPE-5521" in r["text"]
    idg.set_wo_status("WO-1042", "COMPLETED")
    idg.sync_once()
    try:
        r = chat(gw, "maya", "Same customer as yesterday. Did the fix hold?", session="day3")
        assert "CPE-5521" not in r["text"]
    finally:
        idg.set_wo_status("WO-1042", "IN_PROGRESS")
        idg.sync_once()


def test_contractor_reveal_with_masked_pii(gw):
    r = chat(gw, "sam", "Router won't pair at 22 Oak Ave. What's the Wi-Fi password?")
    assert r["ui_intents"] and r["ui_intents"][0]["cpe_sn"] == "CPE-4410"


@pytest.mark.parametrize("user,msg", [
    ("maya", "What's the Wi-Fi password at 22 Oak Ave?"),                          # no relationship
    ("tech-off", WIFI),                                                             # assigned but off shift (ABAC)
    ("raj", WIFI),                                                                  # CSR may reset, never see
    ("priya", "What's the Wi-Fi password at 14 Elm St?"),                           # NOC: no credential access
    ("sam", WIFI),                                                                  # other tenant's customer
    ("sam", "Subscribers report no internet at 14 Elm St. What's going on?"),      # contractor: no topology
    ("ext-t1", "How many active customers in 02139?"),                              # external queue: no data
    ("dana", WIFI),                                                                 # supervisor needs break-glass
])
def test_blocked_scenarios(gw, user, msg):
    r = chat(gw, user, msg, session=f"blocked-{user}")
    assert not r["ui_intents"] and "can't complete" in r["text"], r["text"]
    assert not any(p in json.dumps(r) for p in all_psks())


def test_answers_are_plain_language_not_sql(gw):
    r = chat(gw, "raj", "How many active customers in 02139?")
    assert r["text"] == "There are 24 active customers in 02139." and r["sql"].startswith("SELECT")
    r = chat(gw, "raj", "List devices on PON-01-01")
    assert r["text"].startswith("Found 24 results") and "SELECT" not in r["text"] and "[subscriber]" not in r["text"]
    r = chat(gw, "priya", "Subscribers report no internet at 14 Elm St. What's going on?")
    assert "LOS (critical)" in r["text"]


def test_mop_answer_uses_correct_document(gw):
    r = chat(gw, "maya", "How do I replace an ONT?")
    assert "DOC-MOP-ONT-r2#Procedure" in r["text"] and "POISON" not in r["text"]
    assert r["text"].index("Preconditions") < r["text"].index("Procedure") < r["text"].index("Rollback")


def test_break_glass_two_person(gw):
    dana, lee = token(gw, "dana"), token(gw, "lee")
    bad = gw.post("/v1/break-glass", headers=dana, json={"approver_token": dana["Authorization"][7:],
                                                         "cpe_sn": "CPE-5521", "justification": "customer emergency"})
    assert bad.status_code == 403
    ok = gw.post("/v1/break-glass", headers=dana, json={"approver_token": lee["Authorization"][7:],
                                                        "cpe_sn": "CPE-5521", "justification": "customer emergency"})
    assert ok.status_code == 200
    r = chat(gw, "dana", WIFI)
    ref = r["ui_intents"][0]["reveal_ref"]
    assert gw.post(f"/v1/reveal/{ref}", headers=dana).status_code == 200


def test_authn_fails_closed(gw):
    assert gw.post("/v1/chat", json={"message": "hi"}).status_code == 401
    assert gw.post("/v1/chat", json={"message": "hi"}, headers={"Authorization": "Bearer x.y.z"}).status_code == 401


def test_audit_chain_intact():
    assert audit.verify_chain()
