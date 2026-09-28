from types import SimpleNamespace

from conftest import principal
from switchboard import idg
from switchboard.core import connect, now
from switchboard.policy import LocalPDP, PermitPDP


class FakePermit:
    def __init__(self, decision=True):
        self.decision = decision
        self.check_calls = []
        self.assignments = []
        self.unassignments = []
        self.user_syncs = []
        self.relationships = []
        self.relationship_deletes = []
        self.api = SimpleNamespace(
            tenants=SimpleNamespace(get=lambda _: object(), create=lambda _: None),
            users=SimpleNamespace(
                sync=lambda value: self.user_syncs.append(value),
                assign_role=lambda value: self.assignments.append(value),
                unassign_role=lambda value: self.unassignments.append(value),
            ),
            relationship_tuples=SimpleNamespace(
                create=lambda value: self.relationships.append(value),
                bulk_create=lambda values: self.relationships.extend(values),
                delete=lambda value: self.relationship_deletes.append(value),
            ),
        )

    def check(self, user, action, resource, context=None):
        self.check_calls.append((user, action, resource, context))
        return self.decision


def adapter(fake=None):
    pdp = object.__new__(PermitPDP)
    pdp.permit = fake or FakePermit()
    pdp._known_tenants = set()
    return pdp


def test_permit_check_sends_live_user_and_resource_attributes():
    fake = FakePermit()
    pdp = adapter(fake)
    decision = pdp.check(
        principal("maya"),
        "read",
        {"type": "document", "key": "DOC-1", "attributes": {"classification": "public"}},
    )

    assert decision.allowed
    user, action, resource, _ = fake.check_calls[0]
    assert user["attributes"]["on_shift"] is True
    assert user["attributes"]["device_trust"] == "managed"
    assert user["attributes"]["clearance_level"] == 2
    assert user["attributes"]["is_contractor"] is False
    assert action == "read"
    assert resource["attributes"]["classification"] == "public"
    assert resource["attributes"]["classification_level"] == 0


def test_orphan_subscriber_ownership_sync_uses_internal_tenant():
    fake = FakePermit()
    pdp = adapter(fake)

    pdp.write_tuple("subscriber:S-10000", "owns", "cpe_device:CPE-20002")

    assert fake.relationships[0]["tenant"] == "telco-internal"


def test_permit_relationship_batch_maps_relations_and_tenant():
    fake = FakePermit()
    pdp = adapter(fake)

    pdp.write_tuple_batch([("subscriber:S-10000", "owns", "cpe_device:CPE-20002", None)])

    assert fake.relationships == [{"subject": "subscriber:S-10000", "relation": "owner",
                                   "object": "cpe_device:CPE-20002", "tenant": "telco-internal"}]


def test_document_clearance_uses_ordinal_comparison():
    pdp = LocalPDP()
    assert pdp.check(principal("maya"), "read", {"type": "document", "attributes":
                      {"classification": "internal"}}).allowed
    assert pdp.check(principal("maya"), "read", {"type": "document", "attributes":
                      {"classification": "vendor_nda"}}).allowed
    assert not pdp.check(principal("maya"), "read", {"type": "document", "attributes":
                          {"classification": "restricted"}}).allowed
    assert pdp.check(principal("sam"), "read", {"type": "document", "attributes":
                      {"classification": "internal"}}).allowed


def test_supervisor_assignment_is_an_alternative_to_break_glass_but_not_attribute_gates():
    pdp = LocalPDP()
    # Seed the replicated tuple view consumed by LocalPDP; the app graph's
    # outbox is tested separately and is intentionally asynchronous.
    pdp.write_tuple("user:dana", "assignee", "work_order:WO-ABAC")
    pdp.write_tuple("work_order:WO-ABAC", "serves", "subscriber:SUB-ABAC")
    pdp.write_tuple("subscriber:SUB-ABAC", "owns", "cpe_device:CPE-ABAC")
    assert pdp.check(principal("dana"), "reveal_credential",
                     {"type": "cpe_device", "key": "CPE-ABAC"}, {"step_up_age_s": 1}).allowed
    with connect("platform") as c:
        idg.set_user_attr(c, "dana", {"device_trust": "unmanaged"})
    try:
        denied = pdp.check(principal("dana"), "reveal_credential",
                           {"type": "cpe_device", "key": "CPE-ABAC"}, {"step_up_age_s": 1})
        assert not denied.allowed
        assert denied.reason_code == "CONTEXT_NOT_SATISFIED"
    finally:
        with connect("platform") as c:
            idg.set_user_attr(c, "dana", {"device_trust": "managed"})


def test_reveal_preflight_can_issue_step_up_but_does_not_authorize_secret_access():
    pdp = LocalPDP()
    resource = {"type": "cpe_device", "key": "CPE-5521"}
    assert pdp.can_request_reveal(principal("maya"), resource).allowed
    denied = pdp.check(principal("maya"), "reveal_credential", resource)
    assert not denied.allowed
    assert denied.reason_code == "STEP_UP_REQUIRED"


def test_current_shift_change_denies_before_permit_check():
    fake = FakePermit()
    pdp = adapter(fake)
    with connect("platform") as c:
        idg.set_user_attr(c, "maya", {"on_shift": False})
    try:
        decision = pdp.check(
            principal("maya"), "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
            {"step_up_age_s": 1},
        )

        assert not decision.allowed
        assert decision.reason_code == "CONTEXT_NOT_SATISFIED"
        assert fake.check_calls == []
    finally:
        with connect("platform") as c:
            idg.set_user_attr(c, "maya", {"on_shift": True})


def test_step_up_is_forwarded_fresh_and_permit_drift_fails_closed():
    fake = FakePermit(decision=False)
    pdp = adapter(fake)
    decision = pdp.check(
        principal("maya"), "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
        {"step_up_age_s": 4},
    )

    assert not decision.allowed
    assert decision.reason_code == "PERMIT_DENY"
    assert fake.check_calls[0][0]["attributes"]["step_up_age_s"] == 4
    assert fake.check_calls[0][0]["attributes"]["has_device_link"] is True
    assert fake.check_calls[0][3]["step_up_age_s"] == 4


def test_expired_break_glass_is_denied_and_remote_role_is_revoked():
    fake = FakePermit()
    pdp = adapter(fake)
    LocalPDP.write_tuple(pdp, "user:dana", "break_glass", "cpe_device:CPE-5521", now() - 1)

    assert not pdp.check(
        principal("dana"), "reveal_credential", {"type": "cpe_device", "key": "CPE-5521"},
        {"step_up_age_s": 1},
    ).allowed
    assert pdp.revoke_expired_once() == 1
    assert fake.unassignments == [{"user": "dana", "role": "break_glass", "tenant": "telco-internal",
                                  "resource_instance": "cpe_device:CPE-5521"}]
    assert pdp.expired_tuples() == []


def test_user_role_and_live_attributes_are_synced_to_permit():
    fake = FakePermit()
    pdp = adapter(fake)
    pdp.set_user_attrs("maya", {"on_shift": True})

    assert fake.user_syncs == [{"key": "maya", "attributes": pdp.user_attrs("maya"),
                               "role_assignments": [{"role": "field_technician", "tenant": "telco-internal"}]}]


def test_assignment_and_resource_relationships_sync_with_tenant():
    fake = FakePermit()
    pdp = adapter(fake)
    pdp.write_tuple("user:maya", "assignee", "work_order:WO-1042")
    pdp.write_tuple("work_order:WO-1042", "serves", "subscriber:S-88123")

    assert fake.assignments == [{"user": "maya", "role": "assignee", "tenant": "telco-internal",
                                 "resource_instance": "work_order:WO-1042"}]
    assert fake.relationships == [{"subject": "work_order:WO-1042", "relation": "parent",
                                   "object": "subscriber:S-88123", "tenant": "telco-internal"}]

    try:
        pdp.delete_tuple("work_order:WO-1042", "serves", "subscriber:S-88123")
        assert fake.relationship_deletes == [{"subject": "work_order:WO-1042", "relation": "parent",
                                             "object": "subscriber:S-88123"}]
    finally:
        # This is a session-seeded tuple used by later policy and scenario tests.
        pdp.write_tuple("work_order:WO-1042", "serves", "subscriber:S-88123")


def test_startup_reconciliation_queues_current_users_and_edges():
    with connect("platform") as c:
        before = c.execute("SELECT COALESCE(MAX(id), 0) FROM idg_outbox").fetchone()[0]
        count = idg.enqueue_current_state(c)
        queued = c.execute("SELECT op, payload FROM idg_outbox WHERE id>? ORDER BY id", (before,)).fetchall()

    assert count == len(queued)
    assert any(r[0] == "set_user_attr" and '"user_id": "maya"' in r[1] for r in queued)
    assert any(r[0] == "upsert_tuple" and '"relation": "serves"' in r[1] for r in queued)
