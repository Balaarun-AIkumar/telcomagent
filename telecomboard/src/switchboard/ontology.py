"""Ontology mapping: classification drives canon views, SQL validator denylist, grants and masking."""
from __future__ import annotations

import functools
import re
from pathlib import Path

import yaml

from .core import connect

PATH = Path(__file__).parent / "data" / "ontology.yaml"
BLOCKED = {"pii", "secret"}


@functools.cache
def load() -> dict:
    return yaml.safe_load(PATH.read_text(encoding="utf-8"))


def classification(table: str, col: str) -> str:
    return load()["columns"].get(table, {}).get(col, {}).get("classification", "internal")


def exposed_columns(view: str) -> dict[str, str]:
    """Canon view columns whose *source* classification is not PII/SECRET (text-to-SQL surface)."""
    out = {}
    for name, spec in load()["canon_views"][view]["columns"].items():
        tbl, col = spec["source"].split(".")
        if classification(tbl, col) not in BLOCKED:
            out[name] = spec["expr"]
    return out


def create_scoped_views(conn, scope_subscribers: list[str] | None) -> None:
    """RLS equivalent: scope is applied by server code, never by generated SQL. [] means zero rows (fail closed)."""
    if scope_subscribers is not None and not all(re.fullmatch(r"S-\d{5}", z) for z in scope_subscribers):
        raise ValueError("invalid scope")
    for view, spec in load()["canon_views"].items():
        cols = ", ".join(f"{expr} AS {name}" for name, expr in exposed_columns(view).items())
        conds = [spec["where"]] if spec.get("where") else []
        if scope_subscribers is not None:
            conds.append(f"{spec['scope_col']} IN ({','.join(repr(z) for z in scope_subscribers)})" if scope_subscribers else "0")
        where = f" WHERE {' AND '.join(conds)}" if conds else ""
        conn.execute(f"DROP VIEW IF EXISTS temp.{view}")
        conn.execute(f"CREATE TEMP VIEW {view} AS SELECT {cols} FROM ({spec['base']}){where}")


def grants_sql(role: str = "t2s_reader") -> list[str]:
    """Postgres column grants generated from classification (cloud path)."""
    stmts = []
    for tbl, cols in load()["columns"].items():
        ok = [c for c, s in cols.items() if s["classification"] not in BLOCKED]
        stmts.append(f"GRANT SELECT ({', '.join(ok)}) ON legacy.{tbl} TO {role};")
    return stmts


def propose(table: str, col: str, samples: list[str]) -> str:
    """Annotate step (LLM stand-in): propose a classification with name+value evidence."""
    if re.search(r"psk|pass|secret|key", col):
        return "secret"
    if re.search(r"nm|name|addr_1|ph|email|flg", col) or any(re.fullmatch(r"\d{3}-\d{3}-\d{4}", s) for s in samples):
        return "pii"
    return "internal"


def load_catalog() -> None:
    with connect("platform") as c:
        for tbl, cols in load()["columns"].items():
            for col, s in cols.items():
                c.execute("INSERT OR REPLACE INTO catalog_column_semantics VALUES (?,?,?,?,?,?,?,?)",
                          (tbl, col, s["meaning"], s["ontology"], s["classification"], "approved", 1.0, "ontology.yaml"))


def status_label(field: str, code: str) -> str | None:
    return load()["status_maps"][field].get(code)
