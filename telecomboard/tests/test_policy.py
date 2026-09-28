from pathlib import Path

import yaml

from conftest import principal
from switchboard import idg
from switchboard.policy import pdp

CASES = yaml.safe_load((Path(__file__).parents[1] / "policy" / "policy_matrix.yaml").read_text())["cases"]


def test_policy_matrix_100_percent():
    failures = []
    for case in CASES:
        setup = case.get("setup", {})
        if wo := setup.get("close_wo"):
            idg.set_wo_status(wo, "COMPLETED")
        if wo := setup.get("open_wo"):
            idg.set_wo_status(wo, "IN_PROGRESS")
        idg.sync_once()
        rtype, key = case["resource"].split(":", 1)
        context = case.get("context", {})
        if case["action"] == "reveal_credential" and "step_up_age_s" not in context:
            context = {**context, "step_up_age_s": 1}
        d = pdp().check(principal(case["user"]), case["action"],
                        {"type": rtype, "key": key, "attributes": case.get("attributes", {})}, context)
        if ("allow" if d.allowed else "deny") != case["expect"]:
            failures.append((case["id"], d.reason_code))
    assert not failures, failures
    assert idg.outbox_lag_seconds() == 0


def test_deny_by_default_during_sync_lag():
    idg.set_wo_status("WO-1042", "COMPLETED")
    idg.sync_once()
    idg.set_wo_status("WO-1042", "IN_PROGRESS")  # dispatched, not yet synced
    p = principal("maya")
    assert not pdp().check(p, "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
                           {"step_up_age_s": 1}).allowed
    assert idg.outbox_lag_seconds() >= 0
    idg.sync_once()
    assert pdp().check(p, "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
                       {"step_up_age_s": 1}).allowed


def test_explain_access_path():
    paths = idg.explain_access("maya", "CPE-5521")
    assert ["user:maya", "work_order:WO-1042", "subscriber:S-88123", "cpe_device:CPE-5521"] in paths
