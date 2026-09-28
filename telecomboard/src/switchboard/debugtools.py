"""Debugging non-deterministic runs: trace2test (trace -> replayable golden) and k-run variance reports."""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

from . import auth, orchestrator, telemetry
from .core import connect

VOLATILE = re.compile(r"\b(JOB-\d+|TT-\d+|WO-9\d+|rv_[\w-]+)\b")


def fixtures_dir() -> Path:
    p = Path(os.getenv("SB_TRACE_FIXTURES", Path.cwd() / "evals" / "datasets" / "traces"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def decisions(trace_id: str) -> list[list[str]]:
    with connect("platform") as c:
        rows = c.execute("SELECT action, resource, decision FROM audit_policy_decision WHERE trace_id=?",
                         (trace_id,)).fetchall()
    return sorted([r[0], VOLATILE.sub("<id>", r[1]), r[2]] for r in rows)


def export(trace_id: str, name: str | None = None) -> Path:
    """Turn a live trace into a permanent regression fixture (input, prompt version, policy decisions, tool spans)."""
    spans = [s for s in telemetry.SPAN_LOG if s["trace_id"] == trace_id]
    root = next((s for s in spans if s["name"] == "orchestrator.run"), None)
    if root is None:
        raise KeyError("trace not found in this process's span log")
    with connect("platform") as c:
        actor = c.execute("SELECT actor_id FROM audit_policy_decision WHERE trace_id=? LIMIT 1", (trace_id,)).fetchone()
    fixture = {"trace_id": trace_id, "user": actor[0] if actor else None, "input": root.get("input", ""),
               "prompt_version": root["attrs"].get("switchboard.prompt.refusal_version"),
               "expected_decisions": decisions(trace_id),
               "expected_tools": sorted(s["name"] for s in spans if s["name"].startswith("tool."))}
    path = fixtures_dir() / f"{name or trace_id}.json"
    path.write_text(json.dumps(fixture, indent=1), encoding="utf-8")
    return path


def replay(fixture: dict) -> list[str]:
    """Re-run a fixture; return human-readable mismatches (empty list = still behaves the same)."""
    p = auth.principal_from_token(auth.issue(fixture["user"]))
    r = orchestrator.run(fixture["input"], p, session_id=f"replay-{fixture['trace_id']}")
    tools_now = sorted(s["name"] for s in telemetry.SPAN_LOG if s["trace_id"] == r["trace_id"]
                       and s["name"].startswith("tool."))
    out = []
    if (got := decisions(r["trace_id"])) != fixture["expected_decisions"]:
        out.append(f"policy decisions changed: {got} != {fixture['expected_decisions']}")
    if tools_now != fixture["expected_tools"]:
        out.append(f"tool trajectory changed: {tools_now} != {fixture['expected_tools']}")
    return out


def variance(cases: list[tuple[str, str]], k: int = 3) -> dict:
    """Run each (user, message) k times; report distinct outcomes and pass^k (all runs identical)."""
    report = {}
    for user, msg in cases:
        sigs = Counter()
        for i in range(k):
            r = orchestrator.run(msg, auth.principal_from_token(auth.issue(user)), session_id=f"var-{i}")
            steps = sorted((s, v["status"]) for s, v in r.get("steps", {}).items())
            sigs[json.dumps([steps, VOLATILE.sub("<id>", r["text"])])] += 1
        report[f"{user}: {msg}"] = {"runs": k, "distinct_outcomes": len(sigs), "pass_k": len(sigs) == 1}
    return report
