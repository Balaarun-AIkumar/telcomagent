"""Append-only, hash-chained audit of policy decisions (single writer via BEGIN IMMEDIATE)."""
from __future__ import annotations

import hashlib
import json

from .core import connect, now


def _row_hash(prev: bytes | None, decided_at, actor, action, resource, decision, reason, trace_id) -> bytes:
    canon = json.dumps([decided_at, actor, action, resource, decision, reason, trace_id], sort_keys=True)
    return hashlib.sha256((prev or b"") + canon.encode()).digest()


def record(actor: str, action: str, resource: str, decision: str, reason: dict, trace_id: str | None) -> None:
    reason_s = json.dumps(reason, sort_keys=True)
    c = connect("platform")
    try:
        c.execute("BEGIN IMMEDIATE")
        prev = c.execute("SELECT row_hash FROM audit_policy_decision ORDER BY id DESC LIMIT 1").fetchone()
        prev_h = prev[0] if prev else None
        ts = now()
        h = _row_hash(prev_h, ts, actor, action, resource, decision, reason_s, trace_id)
        c.execute("INSERT INTO audit_policy_decision(decided_at, actor_id, action, resource, decision, reason, trace_id,"
                  " prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                  (ts, actor, action, resource, decision, reason_s, trace_id, prev_h, h))
        c.execute("COMMIT")
    finally:
        c.close()


def verify_chain() -> bool:
    with connect("platform") as c:
        rows = c.execute("SELECT * FROM audit_policy_decision ORDER BY id").fetchall()
    prev = None
    for r in rows:
        if r["prev_hash"] != prev or r["row_hash"] != _row_hash(prev, r["decided_at"], r["actor_id"], r["action"],
                                                                 r["resource"], r["decision"], r["reason"],
                                                                 r["trace_id"]):
            return False
        prev = r["row_hash"]
    return True
