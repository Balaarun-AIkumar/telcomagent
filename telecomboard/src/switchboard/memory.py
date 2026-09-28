"""Long-term episodic memory with identity scoping and read-time re-authorization."""
from __future__ import annotations

import json
import uuid

from . import llm
from .context import Principal
from .core import connect, now
from .policy import pdp
from .redaction import find_secrets, mask_pii, scrub


def store_episode(p: Principal, subject_ref: str | None, summary: str, ttl_days: int = 30) -> bool:
    summary = mask_pii(scrub(summary))
    if find_secrets(summary):
        return False
    t = now()
    with connect("platform") as c:
        c.execute("INSERT INTO memory_episode VALUES (?,?,?,?,?,?,?)",
                  (str(uuid.uuid4()), p.user_id, subject_ref, summary, json.dumps(llm.embed(summary)), t,
                   t + ttl_days * 86400))
    return True


def recall(p: Principal, query: str, k: int = 3) -> list[dict]:
    with connect("platform") as c:
        rows = c.execute("SELECT subject_ref, summary, embedding, created_at FROM memory_episode WHERE user_id=?"
                         " AND expires_at > ? ORDER BY created_at DESC LIMIT 50", (p.user_id, now())).fetchall()
    qv = llm.embed(query)
    scored = sorted(rows, key=lambda r: (-llm.cosine(qv, json.loads(r["embedding"])) - r["created_at"] * 1e-12))
    out = []
    for r in scored:
        res = {"type": "memory_episode", "key": "*", "attributes": {"subject_ref": r["subject_ref"]}}
        if pdp().check(p, "read", res).allowed:  # re-authorized *now*, not when written
            out.append({"subject_ref": r["subject_ref"], "summary": r["summary"], "created_at": r["created_at"]})
        if len(out) >= k:
            break
    return out


def purge_expired() -> int:
    with connect("platform") as c:
        return c.execute("DELETE FROM memory_episode WHERE expires_at <= ?", (now(),)).rowcount
