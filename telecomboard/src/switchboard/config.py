"""Small startup helpers: local settings and an explicit, credential-free demo mode."""
from __future__ import annotations

import os
import re
from pathlib import Path


def load_env(path: Path = Path(".env")) -> None:
    """Shell values take precedence. Values are never executed or printed."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                os.environ.setdefault(key.strip(), value)


def offline() -> None:
    for key in list(os.environ):
        if key.startswith(("GOOGLE_", "PERMIT_", "NEO4J_", "LANGFUSE_", "OTEL_")) or (
            key.startswith("SB_") and key.endswith("_URL")
        ):
            os.environ.pop(key)


def require_policy_service() -> None:
    """Fail clearly at startup instead of launching a demo with every remote check broken."""
    if not os.getenv("PERMIT_API_KEY"):
        return
    import httpx

    try:
        url = (os.getenv("PERMIT_PDP_URL") or "http://localhost:7766").rstrip("/")
        response = httpx.get(url + "/health", timeout=3)
        response.raise_for_status()
        if response.json().get("status") != "ok":
            raise ValueError("PDP unhealthy")
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(
            "Permit is configured but its PDP is unavailable. Start Docker Desktop, then run: "
            "docker compose --env-file .env -f compose.permit.yml up -d. "
            "For an explicitly local demo instead, use --offline --demo before serve."
        ) from exc
