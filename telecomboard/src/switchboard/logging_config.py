"""Operational events contain metadata, never requests, tool payloads or credentials."""
import json
import logging

from .context import current_trace_id


def event(name: str, **fields: str | int | float) -> None:
    logging.getLogger("switchboard.events").info(json.dumps(
        {"event": name, "trace_id": current_trace_id.get(), **fields}, sort_keys=True))


def setup() -> None:
    logger = logging.getLogger("switchboard.events")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
