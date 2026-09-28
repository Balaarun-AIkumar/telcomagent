"""Request-scoped identity (never placed in LLM-visible state) and trace context."""
from __future__ import annotations

import secrets
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    tenant: str
    token: str | None = field(default=None, repr=False)
    auth_time: float | None = None

    @property
    def key(self) -> str:
        return f"user:{self.user_id}"


current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)
current_trace_id: ContextVar[str] = ContextVar("current_trace_id", default="")


def new_trace_id() -> str:
    tid = secrets.token_hex(16)
    current_trace_id.set(tid)
    return tid


def require_principal() -> Principal:
    p = current_principal.get()
    if p is None:
        raise PermissionError("no authenticated principal in request context")
    return p
