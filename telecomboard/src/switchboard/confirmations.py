"""Single-use confirmation of a specific write, bound to its user and arguments."""
from __future__ import annotations

import hashlib
import json
import secrets
from contextvars import ContextVar

from .core import connect, now

approved_action: ContextVar[tuple[str, dict] | None] = ContextVar("approved_action", default=None)


def create(user_id: str, action: str, args: dict, ttl: int = 120) -> str:
    ref = "cf_" + secrets.token_urlsafe(24)
    with connect() as conn:
        conn.execute("INSERT INTO action_confirmation VALUES (?,?,?,?,?,NULL)",
                     (hashlib.sha256(ref.encode()).digest(), user_id, action,
                      json.dumps(args, sort_keys=True), now() + ttl))
    return ref


def consume(ref: str, user_id: str, action: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "UPDATE action_confirmation SET used_at=? WHERE ref_hash=? AND user_id=? AND action=? "
            "AND used_at IS NULL AND expires_at>? RETURNING args",
            (now(), hashlib.sha256(ref.encode()).digest(), user_id, action, now()),
        ).fetchone()
    return json.loads(row[0]) if row else None
