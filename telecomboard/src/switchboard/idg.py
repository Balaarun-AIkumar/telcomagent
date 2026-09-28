"""Identity graph (source of truth, temporal edges) + transactional outbox + idg-sync worker."""
from __future__ import annotations

import json
import threading

from . import telemetry
from .core import connect, now
from .policy import PermitPDP, pdp


def _outbox(c, op: str, payload: dict) -> None:
    c.execute("INSERT INTO idg_outbox(op, payload, created_at) VALUES (?,?,?)", (op, json.dumps(payload), now()))


def add_edge(c, src_type, src_id, rel, dst_type, dst_id) -> None:
    """Temporal exclusion (Postgres: EXCLUDE USING gist) enforced here for SQLite."""
    open_edge = c.execute("SELECT 1 FROM idg_edge WHERE src_type=? AND src_id=? AND rel=? AND dst_type=? AND dst_id=?"
                          " AND valid_to IS NULL", (src_type, src_id, rel, dst_type, dst_id)).fetchone()
    if open_edge:
        return
    c.execute("INSERT INTO idg_edge(src_type, src_id, rel, dst_type, dst_id, valid_from) VALUES (?,?,?,?,?,?)",
              (src_type, src_id, rel, dst_type, dst_id, now()))
    _outbox(c, "upsert_tuple", {"subject": f"{src_type}:{src_id}", "relation": rel, "object": f"{dst_type}:{dst_id}"})


def close_edge(c, src_type, src_id, rel, dst_type, dst_id) -> None:
    c.execute("UPDATE idg_edge SET valid_to=? WHERE src_type=? AND src_id=? AND rel=? AND dst_type=? AND dst_id=?"
              " AND valid_to IS NULL", (now(), src_type, src_id, rel, dst_type, dst_id))
    # Revoke the local mirror in this transaction even when the remote PDP is offline.
    c.execute("DELETE FROM pdp_tuple WHERE subject=? AND relation=? AND object=?",
              (f"{src_type}:{src_id}", rel, f"{dst_type}:{dst_id}"))
    _outbox(c, "delete_tuple", {"subject": f"{src_type}:{src_id}", "relation": rel, "object": f"{dst_type}:{dst_id}"})


def set_user_attr(c, user_id: str, attrs: dict) -> None:
    """Update app-owned current facts; PDP copies are only sync conveniences."""
    current = c.execute("SELECT attrs FROM app_user_attr WHERE user_id=?", (user_id,)).fetchone()
    merged = {**(json.loads(current[0]) if current else {}), **attrs}
    c.execute("INSERT OR REPLACE INTO app_user_attr VALUES (?,?)", (user_id, json.dumps(merged)))
    _outbox(c, "set_user_attr", {"user_id": user_id, "attrs": attrs})


def set_user_role(c, user_id: str, role: str, tenant: str | None = None) -> None:
    """Update a user's source-of-truth role/tenant and enqueue a full Permit user sync."""
    if tenant is None:
        c.execute("UPDATE app_user SET role=? WHERE user_id=?", (role, user_id))
    else:
        c.execute("UPDATE app_user SET role=?, tenant=? WHERE user_id=?", (role, tenant, user_id))
    if c.execute("SELECT changes()").fetchone()[0] != 1:
        raise KeyError(user_id)
    set_user_attr(c, user_id, {})


def enqueue_current_state(c) -> int:
    """Queue a full current-state reconciliation for a newly enabled Permit environment."""
    count = 0
    users = c.execute("SELECT user_id FROM app_user ORDER BY user_id").fetchall()
    for row in users:
        _outbox(c, "set_user_attr", {"user_id": row[0], "attrs": {}})
        count += 1
    edges = c.execute("SELECT src_type, src_id, rel, dst_type, dst_id FROM idg_edge "
                       "WHERE valid_to IS NULL ORDER BY src_type, src_id, rel, dst_type, dst_id").fetchall()
    for row in edges:
        _outbox(c, "upsert_tuple", {"subject": f"{row[0]}:{row[1]}", "relation": row[2],
                                    "object": f"{row[3]}:{row[4]}"})
        count += 1
    # Break-glass grants are not ordinary IDG graph edges; mirror only those still live.
    grants = c.execute("SELECT subject, relation, object, expires_at FROM pdp_tuple "
                       "WHERE relation='break_glass' AND expires_at > ?", (now(),)).fetchall()
    for row in grants:
        _outbox(c, "upsert_tuple", {"subject": row[0], "relation": row[1], "object": row[2],
                                    "expires_at": row[3]})
        count += 1
    return count


def set_wo_status(wo_id: str, status: str) -> None:
    """Operational event: WO status change updates legacy row, identity graph and outbox in ONE transaction."""
    with connect("platform") as c:
        wo = c.execute("SELECT wo_id, sbscr_ref, tech_id FROM legacy.wo_hdr WHERE wo_id=?", (wo_id,)).fetchone()
        if wo is None:
            raise KeyError(wo_id)
        code = {"DISPATCHED": "D", "IN_PROGRESS": "I", "COMPLETED": "C", "CANCELLED": "X"}[status]
        c.execute("UPDATE legacy.wo_hdr SET sts_cd=? WHERE wo_id=?", (code, wo_id))
        if status in ("DISPATCHED", "IN_PROGRESS"):
            add_edge(c, "user", wo["tech_id"], "assignee", "work_order", wo_id)
        else:
            close_edge(c, "user", wo["tech_id"], "assignee", "work_order", wo_id)


def outbox_lag_seconds() -> float:
    with connect("platform") as c:
        r = c.execute("SELECT MIN(created_at) FROM idg_outbox WHERE published_at IS NULL").fetchone()
    return max(0.0, now() - r[0]) if r and r[0] else 0.0


_leader = threading.Lock()  # Postgres deployment: pg_try_advisory_lock
_sync_stop = threading.Event()
_sync_thread: threading.Thread | None = None


def sync_once(limit: int = 500) -> int:
    """Publish pending outbox rows in id order (publishes are idempotent, so at-least-once is safe)."""
    if not _leader.acquire(blocking=False):
        return 0
    try:
        engine = pdp()
        telemetry.METRICS["outbox_lag_seconds"] = outbox_lag_seconds()
        with connect("platform") as c:
            rows = c.execute("SELECT id, op, payload FROM idg_outbox WHERE published_at IS NULL ORDER BY id LIMIT ?",
                             (limit,)).fetchall()
        i = 0
        while i < len(rows):
            r = rows[i]
            p = json.loads(r["payload"])
            if (isinstance(engine, PermitPDP) and r["op"] == "upsert_tuple"
                    and not p["subject"].startswith("user:")):
                batch = []
                row_ids = []
                while i < len(rows) and len(batch) < 500:
                    candidate = rows[i]
                    payload = json.loads(candidate["payload"])
                    if (candidate["op"] != "upsert_tuple" or payload["subject"].startswith("user:")):
                        break
                    batch.append((payload["subject"], payload["relation"], payload["object"],
                                  payload.get("expires_at")))
                    row_ids.append(candidate["id"])
                    i += 1
                engine.write_tuple_batch(batch)
                stamp = now()
                with connect("platform") as c:
                    c.executemany("UPDATE idg_outbox SET published_at=? WHERE id=?",
                                  [(stamp, row_id) for row_id in row_ids])
                continue
            if r["op"] == "upsert_tuple":
                engine.write_tuple(p["subject"], p["relation"], p["object"], p.get("expires_at"))
            elif r["op"] == "delete_tuple":
                engine.delete_tuple(p["subject"], p["relation"], p["object"])
            else:
                engine.set_user_attrs(p["user_id"], p["attrs"])
            with connect("platform") as c:
                c.execute("UPDATE idg_outbox SET published_at=? WHERE id=?", (now(), r["id"]))
            i += 1
        return len(rows)
    finally:
        _leader.release()


def start_sync_worker(interval_s: float = 1.0) -> None:
    """Retry the transactional outbox while the gateway is running with Permit enabled."""
    global _sync_thread
    if _sync_thread is not None and _sync_thread.is_alive():
        return
    _sync_stop.clear()

    def run() -> None:
        while not _sync_stop.wait(interval_s):
            try:
                sync_once()
            except Exception as exc:
                # Leave the event pending; next interval retries it. Do not log payloads.
                print(f"Permit IDG sync failed ({type(exc).__name__}); will retry")

    _sync_thread = threading.Thread(target=run, name="permit-idg-sync", daemon=True)
    _sync_thread.start()


def stop_sync_worker() -> None:
    _sync_stop.set()
    if _sync_thread is not None:
        _sync_thread.join(timeout=2)


def break_glass(requester: str, approver: str, cpe_sn: str, justification: str, minutes: int = 15) -> bool:
    """Two-person, time-boxed access. Caller must have verified both principals are supervisors."""
    if requester == approver or len(justification.strip()) < 10:
        return False
    with connect("platform") as c:
        _outbox(c, "upsert_tuple", {"subject": f"user:{requester}", "relation": "break_glass",
                                    "object": f"cpe_device:{cpe_sn}", "expires_at": now() + minutes * 60})
    sync_once()
    return True


def explain_access(user_id: str, cpe_sn: str) -> list[list[str]]:
    """'Why can this user reach this device right now?' via recursive CTE over current edges."""
    sql = """
    WITH RECURSIVE e AS (
      SELECT src_type||':'||src_id AS s, dst_type||':'||dst_id AS d FROM idg_edge WHERE valid_to IS NULL
    ), path(node, hops, depth) AS (
      SELECT d, s||'>'||d, 1 FROM e WHERE s = 'user:'||?
      UNION ALL
      SELECT e.d, p.hops||'>'||e.d, p.depth+1 FROM path p JOIN e ON e.s = p.node
      WHERE p.depth < 5 AND instr(p.hops, e.d) = 0
    ) SELECT hops FROM path WHERE node = 'cpe_device:'||?"""
    with connect("platform") as c:
        return [r[0].split(">") for r in c.execute(sql, (user_id, cpe_sn)).fetchall()]
