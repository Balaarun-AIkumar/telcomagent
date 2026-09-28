"""Policy decision point. Local engine mirrors the Permit.io model (RBAC + ABAC + ReBAC);
PermitPDP delegates to a real Permit PDP when PERMIT_API_KEY is set. The LLM is never the policy engine."""
from __future__ import annotations

import json
import os
import math
import logging
import threading
from dataclasses import dataclass, field

from .core import connect, now

ACTIVE_WO = {"DISPATCHED", "IN_PROGRESS"}
DOC_CLASSES = {
    "field_technician": {"public", "internal", "vendor_nda"},
    "csr_tier1": {"public", "internal"},
    "csr_external": {"public"},
    "noc_engineer": {"public", "internal", "restricted"},
    "contractor": {"public", "vendor_nda"},
    "supervisor": {"public", "internal", "vendor_nda", "restricted"},
    "automation": {"public", "internal"},
}
# Ordinal mapping used by document ABAC. `vendor_nda` is this app's
# confidential-class label; support both names for compatibility.
CLASSIFICATION_LEVELS = {"public": 0, "internal": 1, "vendor_nda": 2,
                         "confidential": 2, "restricted": 3}
ROLE_CLEARANCE = {
    "csr_external": 0, "csr_tier1": 1, "automation": 1,
    "field_technician": 2, "contractor": 2,
    "noc_engineer": 3, "supervisor": 3,
}
# Role-only grants (resource_type, action)
ROLE_GRANTS: dict[str, set[tuple[str, str]]] = {
    "csr_tier1": {("subscriber", "read_profile"), ("subscriber", "read_pii"), ("subscriber", "trigger_psk_reset"),
                  ("cpe_device", "read_status"), ("ticket", "read"), ("ticket", "create"), ("ticket", "add_note")},
    "csr_external": {("ticket", "read"), ("ticket", "create")},
    "field_technician": {("ticket", "read"), ("ticket", "create"), ("ticket", "add_note")},
    "noc_engineer": {("subscriber", "read_profile"), ("cpe_device", "read_status"), ("cpe_device", "read_config"),
                     ("topology", "read"), ("ticket", "read"), ("ticket", "create"), ("ticket", "add_note"),
                     ("work_order", "read"), ("work_order", "share_with_vendor")},
    "contractor": set(),
    "supervisor": {("subscriber", "read_profile"), ("subscriber", "read_pii"), ("cpe_device", "read_status"),
                   ("cpe_device", "read_config"), ("topology", "read"), ("work_order", "read"),
                   ("work_order", "update"), ("work_order", "share_with_vendor"), ("ticket", "read"),
                   ("ticket", "create"), ("ticket", "add_note")},
    "automation": {("work_order", "read")},
}
# Grants derived from the relationship `field_access` (work_order#assignee -> serves -> owns)
REL_GRANTS: dict[str, set[tuple[str, str]]] = {
    "field_technician": {("subscriber", "read_profile"), ("subscriber", "read_pii"), ("cpe_device", "read_status"),
                         ("cpe_device", "read_config"), ("cpe_device", "reveal_credential"), ("cpe_device", "reboot"),
                         ("work_order", "read"), ("work_order", "update"), ("work_order", "share_with_vendor")},
    "contractor": {("subscriber", "read_profile"), ("cpe_device", "read_status"),
                   ("cpe_device", "reveal_credential"), ("work_order", "read")},
}
MASK_PII_ROLES = {"contractor", "csr_external", "noc_engineer"}
ALTERNATIVES = {
    "reveal_credential": ["Send a Wi-Fi password reset to the account holder's number on file",
                          "Open a ticket for an assigned field technician"],
    "read_pii": ["Ask the account holder to verify details directly"],
    "read_profile": ["Open a ticket so an authorized team can follow up"],
}


@dataclass
class Decision:
    allowed: bool
    reason_code: str
    mask_pii: bool = False
    alternatives: list[str] = field(default_factory=list)


class LocalPDP:
    """In-process PDP over the replicated tuple store (pdp_tuple), fed only by idg-sync."""

    def _tuples(self, c, subject=None, relation=None, obj=None) -> list[tuple[str, str, str]]:
        q, args = "SELECT subject, relation, object FROM pdp_tuple WHERE (expires_at IS NULL OR expires_at > ?)", [now()]
        for col, v in (("subject", subject), ("relation", relation), ("object", obj)):
            if v is not None:
                q += f" AND {col}=?"
                args.append(v)
        return [tuple(r) for r in c.execute(q, args).fetchall()]

    def user_attrs(self, user_id: str) -> dict:
        with connect("platform") as c:
            # Read current app-owned facts on every check, not an asynchronously synced PDP copy.
            r = c.execute("SELECT attrs FROM app_user_attr WHERE user_id=?", (user_id,)).fetchone()
        return json.loads(r[0]) if r else {}

    def expired_tuples(self) -> list[tuple[str, str, str, float]]:
        with connect("platform") as c:
            rows = c.execute("SELECT subject, relation, object, expires_at FROM pdp_tuple "
                             "WHERE expires_at IS NOT NULL AND expires_at <= ?", (now(),)).fetchall()
        return [(r[0], r[1], r[2], r[3]) for r in rows]

    def field_access(self, user_id: str, rtype: str, key: str) -> bool:
        with connect("platform") as c:
            wos = {o for _, _, o in self._tuples(c, f"user:{user_id}", "assignee")}
            if rtype == "work_order":
                return f"work_order:{key}" in wos
            subs = {o for wo in wos for _, _, o in self._tuples(c, wo, "serves")}
            if rtype == "subscriber":
                return f"subscriber:{key}" in subs
            if rtype == "cpe_device":
                return any(self._tuples(c, s, "owns", f"cpe_device:{key}") for s in subs)
        return False

    def break_glass(self, user_id: str, rtype: str, key: str) -> bool:
        with connect("platform") as c:
            return bool(self._tuples(c, f"user:{user_id}", "break_glass", f"{rtype}:{key}"))

    def check(self, principal, action: str, resource: dict, context: dict | None = None) -> Decision:
        context = context or {}
        role, rtype, key = principal.role, resource["type"], resource.get("key", "*")
        mask = role in MASK_PII_ROLES
        alts = ALTERNATIVES.get(action, [])
        if rtype == "document":
            cls = resource.get("attributes", {}).get("classification")
            clearance = ROLE_CLEARANCE.get(role)
            ok = clearance is not None if cls is None else (
                cls in CLASSIFICATION_LEVELS and clearance is not None
                and clearance >= CLASSIFICATION_LEVELS[cls]
            )  # None: capability probe
            return Decision(ok, "OK" if ok else "DOC_CLASSIFICATION", mask)
        if rtype == "memory_episode":
            subj = resource.get("attributes", {}).get("subject_ref") or ""
            st, _, sk = subj.partition(":")
            return self.check(principal, "read_profile", {"type": st, "key": sk}) if sk else Decision(True, "OK")
        if action == "reveal_credential":
            return self._reveal(principal, rtype, key, context, mask, alts)
        if (rtype, action) in ROLE_GRANTS.get(role, set()):
            return Decision(True, "OK", mask)
        if (rtype, action) in REL_GRANTS.get(role, set()):
            if key == "*":  # capability probe: role may act on *some* related resource
                return Decision(True, "OK_SCOPED", mask)
            if self.field_access(principal.user_id, rtype, key):
                return Decision(True, "OK_REL", mask)
            return Decision(False, "NO_RELATIONSHIP", mask, alts)
        return Decision(False, "ROLE_NOT_PERMITTED", mask, alts)

    def can_request_reveal(self, principal, resource: dict) -> Decision:
        """Preflight a step-up challenge without authorizing or returning a credential."""
        return self._reveal(principal, resource["type"], resource.get("key", "*"), {},
                            principal.role in MASK_PII_ROLES, ALTERNATIVES["reveal_credential"],
                            require_step_up=False)

    def _reveal(self, principal, rtype, key, context, mask, alts, *, require_step_up=True) -> Decision:
        if rtype != "cpe_device":
            return Decision(False, "ROLE_NOT_PERMITTED", mask, alts)
        # Recent step-up is mandatory for every role, including supervisors using break-glass.
        age = context.get("step_up_age_s")
        if require_step_up and (not isinstance(age, (int, float)) or not math.isfinite(age) or not 0 <= age < 300):
            return Decision(False, "STEP_UP_REQUIRED", mask, alts)
        attrs = self.user_attrs(principal.user_id)
        if attrs.get("on_shift") is not True or attrs.get("device_trust") != "managed":
            return Decision(False, "CONTEXT_NOT_SATISFIED", mask, alts)
        if principal.role == "contractor" and attrs.get("cert_valid") is not True:
            return Decision(False, "CERT_INVALID", mask, alts)
        role_permitted = ((rtype, "reveal_credential") in REL_GRANTS.get(principal.role, set())
                          or principal.role == "supervisor")
        if not role_permitted:
            return Decision(False, "ROLE_NOT_PERMITTED", mask, alts)
        assigned = key != "*" and self.field_access(principal.user_id, rtype, key)
        break_glass = key != "*" and self.break_glass(principal.user_id, rtype, key)
        if not (assigned or break_glass):
            return Decision(False, "NO_RELATIONSHIP", mask, alts)
        return Decision(True, "OK_REL" if assigned else "BREAK_GLASS", mask)

    # Tuple store writes: only called by idg-sync
    def write_tuple(self, subject: str, relation: str, obj: str, expires_at: float | None = None) -> None:
        with connect("platform") as c:
            c.execute("INSERT OR REPLACE INTO pdp_tuple VALUES (?,?,?,?)", (subject, relation, obj, expires_at))

    def delete_tuple(self, subject: str, relation: str, obj: str) -> None:
        with connect("platform") as c:
            c.execute("DELETE FROM pdp_tuple WHERE subject=? AND relation=? AND object=?", (subject, relation, obj))

    def set_user_attrs(self, user_id: str, attrs: dict) -> None:
        with connect("platform") as c:
            cur = c.execute("SELECT attrs FROM pdp_user_attr WHERE user_id=?", (user_id,)).fetchone()
            merged = {**(json.loads(cur[0]) if cur else {}), **attrs}
            c.execute("INSERT OR REPLACE INTO pdp_user_attr VALUES (?,?)", (user_id, json.dumps(merged)))


class PermitPDP(LocalPDP):
    """Permit evaluator with app-side live-attribute guard and fail-closed tuple sync."""

    def __init__(self) -> None:
        from permit.sync import Permit  # optional extra

        self.permit = Permit(
            pdp=os.getenv("PERMIT_PDP_URL", "http://localhost:7766"),
            token=os.environ["PERMIT_API_KEY"],
        )
        self._known_tenants: set[str] = set()
        self._expiry_stop = threading.Event()
        self._expiry_thread = threading.Thread(target=self._expiry_loop, name="permit-tuple-expiry", daemon=True)
        self._expiry_thread.start()

    def check(self, principal, action, resource, context=None) -> Decision:
        context = context or {}
        # Local PDP is an independent, fail-closed guard. It prevents stale/expired or
        # overbroad Permit facts from bypassing app checks while Permit policy is evaluated.
        local = super().check(principal, action, resource, context)
        if not local.allowed:
            return local

        rtype = resource["type"]
        key = resource.get("key", "*")
        resource_attrs = resource.get("attributes") or {}
        if rtype == "memory_episode":
            subject_ref = resource_attrs.get("subject_ref")
            st, _, sk = (subject_ref or "").partition(":")
            if not sk:
                # The caller's SQL query is scoped to this user's memory rows.
                return local
            permit_action = "read_profile"
            permit_resource = {"type": st, "key": sk, "tenant": principal.tenant}
        elif (key == "*" and (rtype, action) not in ROLE_GRANTS.get(principal.role, set())
              and not (rtype == "document" and resource_attrs.get("classification") is not None)):
            # Wildcard requests are capability probes, not object access.
            return local
        else:
            permit_action = action
            permit_resource = {"type": rtype, "tenant": principal.tenant}
            if key != "*":
                permit_resource["key"] = key
            if resource_attrs:
                permit_resource["attributes"] = dict(resource_attrs)
                if rtype == "document":
                    cls = resource_attrs.get("classification")
                    if cls in CLASSIFICATION_LEVELS:
                        permit_resource["attributes"]["classification_level"] = CLASSIFICATION_LEVELS[cls]

        # JIT attributes take precedence over any profile attributes stored in Permit.
        # `context` is computed for this request (notably step_up_age_s at redemption).
        user_attrs = self.user_attrs(principal.user_id)
        user_attrs.update({"role": principal.role, "tenant": principal.tenant,
                           "clearance_level": ROLE_CLEARANCE.get(principal.role, -1),
                           "is_contractor": principal.role == "contractor"})
        user_attrs.update(context)
        if action == "reveal_credential":
            user_attrs["has_device_link"] = bool(
                key != "*" and (self.field_access(principal.user_id, rtype, key)
                                or self.break_glass(principal.user_id, rtype, key))
            )
        permit_user = {"key": principal.user_id, "attributes": user_attrs}
        try:
            ok = self.permit.check(permit_user, permit_action, permit_resource, context=context)
        except Exception as exc:
            logging.getLogger(__name__).warning("permit_unavailable type=%s", type(exc).__name__)
            return Decision(False, "POLICY_UNAVAILABLE", local.mask_pii, local.alternatives)
        return local if ok else Decision(False, "PERMIT_DENY", local.mask_pii,
                                         ALTERNATIVES.get(action, local.alternatives))

    def _user_record(self, user_id: str) -> tuple[str, str, dict]:
        with connect("platform") as c:
            row = c.execute("SELECT role, tenant FROM app_user WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError(user_id)
        return row[0], row[1], self.user_attrs(user_id)

    def _resource_tenant(self, resource_instance: str) -> str:
        rtype, _, key = resource_instance.partition(":")
        with connect("platform") as c:
            if rtype == "work_order":
                row = c.execute("SELECT tenant FROM legacy.wo_hdr WHERE wo_id=?", (key,)).fetchone()
            elif rtype == "subscriber":
                row = c.execute("SELECT tenant FROM legacy.wo_hdr WHERE sbscr_ref=? "
                                "ORDER BY tenant LIMIT 1", (key,)).fetchone()
            elif rtype == "cpe_device":
                row = c.execute("SELECT w.tenant FROM legacy.cpe_inv d JOIN legacy.wo_hdr w "
                                "ON w.sbscr_ref=d.sbscr_ref WHERE d.cpe_sn=? ORDER BY w.tenant LIMIT 1",
                                (key,)).fetchone()
            else:
                row = None
            if row is None and rtype in {"subscriber", "cpe_device"}:
                # Ownership links also exist for subscribers with no work order yet.
                # They belong to the app's sole non-contractor tenant; fail closed if
                # the data model no longer has one unambiguous internal tenant.
                tenants = {r[0] for r in c.execute(
                    "SELECT DISTINCT tenant FROM app_user WHERE role != 'contractor'")}
                if len(tenants) == 1:
                    return next(iter(tenants))
                if "telco-internal" in tenants:
                    return "telco-internal"
        if row is None:
            raise KeyError(f"no Permit tenant for resource {resource_instance}")
        return row[0]

    def _ensure_tenant(self, tenant: str) -> None:
        if tenant in self._known_tenants:
            return
        try:
            existing = self.permit.api.tenants.get(tenant)
        except Exception:
            # Create is idempotent for an existing tenant in Permit; failures still
            # propagate so the transactional outbox remains pending and retries.
            existing = None
        if existing is None:
            self.permit.api.tenants.create({"key": tenant, "name": tenant})
        self._known_tenants.add(tenant)

    def write_tuple(self, subject, relation, obj, expires_at=None) -> None:
        if subject.startswith("user:"):
            user_id = subject.split(":", 1)[1]
            _, tenant, _ = self._user_record(user_id)
            self._ensure_tenant(tenant)
            if relation not in {"assignee", "break_glass"}:
                raise ValueError(f"unsupported user relationship: {relation}")
            self.permit.api.users.assign_role({"user": user_id, "role": relation,
                                                "tenant": tenant, "resource_instance": obj})
        else:
            tenant = self._resource_tenant(subject)
            permit_relation = {"serves": "parent", "owns": "owner"}.get(relation, relation)
            self.permit.api.relationship_tuples.create({"subject": subject, "relation": permit_relation,
                                                          "object": obj, "tenant": tenant})
        # Commit the local mirror only after Permit accepted the remote write. If it fails,
        # the outbox row remains pending and the local relationship check denies access.
        super().write_tuple(subject, relation, obj, expires_at)

    def write_tuple_batch(self, tuples: list[tuple[str, str, str, float | None]]) -> None:
        """Publish resource relationship tuples through Permit's bounded bulk endpoint."""
        operations = []
        for subject, relation, obj, _expires_at in tuples:
            if subject.startswith("user:"):
                raise ValueError("user role assignments must use write_tuple")
            tenant = self._resource_tenant(subject)
            permit_relation = {"serves": "parent", "owns": "owner"}.get(relation, relation)
            operations.append({"subject": subject, "relation": permit_relation,
                               "object": obj, "tenant": tenant})
        self.permit.api.relationship_tuples.bulk_create(operations)
        for subject, relation, obj, expires_at in tuples:
            super().write_tuple(subject, relation, obj, expires_at)

    def delete_tuple(self, subject, relation, obj) -> None:
        # Revoke locally first; if Permit is unavailable, local checks still deny access.
        super().delete_tuple(subject, relation, obj)
        self._delete_remote_tuple(subject, relation, obj)

    def _delete_remote_tuple(self, subject: str, relation: str, obj: str) -> None:
        if subject.startswith("user:"):
            user_id = subject.split(":", 1)[1]
            _, tenant, _ = self._user_record(user_id)
            self.permit.api.users.unassign_role({"user": user_id, "role": relation,
                                                  "tenant": tenant, "resource_instance": obj})
        else:
            permit_relation = {"serves": "parent", "owns": "owner"}.get(relation, relation)
            self.permit.api.relationship_tuples.delete({"subject": subject, "relation": permit_relation,
                                                         "object": obj})

    def revoke_expired_once(self) -> int:
        """Revoke expired Permit assignments; local tuple filtering denies immediately meanwhile."""
        rows = self.expired_tuples()
        revoked = 0
        for subject, relation, obj, _ in rows:
            self._delete_remote_tuple(subject, relation, obj)
            super().delete_tuple(subject, relation, obj)
            revoked += 1
        return revoked

    def _expiry_loop(self) -> None:
        while not self._expiry_stop.wait(1.0):
            try:
                self.revoke_expired_once()
            except Exception as exc:
                # Leave the expired row for retry; `_tuples` already excludes it by time.
                logging.getLogger(__name__).warning("permit_expiry_retry type=%s", type(exc).__name__)

    def set_user_attrs(self, user_id, attrs) -> None:
        super().set_user_attrs(user_id, attrs)
        role, tenant, current_attrs = self._user_record(user_id)
        self._ensure_tenant(tenant)
        # Directory data is kept in sync as a fallback; each check above still sends JIT attrs.
        self.permit.api.users.sync({"key": user_id, "attributes": current_attrs,
                                    "role_assignments": [{"role": role, "tenant": tenant}]})


_pdp: LocalPDP | None = None


def pdp() -> LocalPDP:
    global _pdp
    if _pdp is None:
        _pdp = PermitPDP() if os.getenv("PERMIT_API_KEY") else LocalPDP()
    return _pdp
