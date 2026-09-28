"""Secret-by-reference: hashed, single-use, short-TTL reveal grants. PSKs are never stored here."""
from __future__ import annotations

import hashlib
import secrets

from .core import connect, now


def _h(ref: str) -> bytes:
    return hashlib.sha256(ref.encode()).digest()


def create_grant(grantee_id: str, cpe_sn: str, work_order: str, trace_id: str, ttl: int = 60) -> str:
    ref = "rv_" + secrets.token_urlsafe(16)
    t = now()
    with connect("platform") as c:
        c.execute("INSERT INTO reveal_grant(grant_hash, grantee_id, cpe_sn, work_order, trace_id, created_at, expires_at)"
                  " VALUES (?,?,?,?,?,?,?)", (_h(ref), grantee_id, cpe_sn, work_order, trace_id or "-", t, t + ttl))
    return ref


def redeem(ref: str, grantee_id: str) -> dict | None:
    """Atomic single use. None means expired, reused or wrong user."""
    with connect("platform") as c:
        r = c.execute("UPDATE reveal_grant SET used_at=? WHERE grant_hash=? AND grantee_id=? AND used_at IS NULL"
                      " AND expires_at > ? RETURNING cpe_sn, work_order", (now(), _h(ref), grantee_id, now())).fetchone()
    return dict(r) if r else None
