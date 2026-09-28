"""Text-to-SQL over the undocumented legacy schema: profile -> generate -> validate (sqlglot AST) -> execute scoped."""
from __future__ import annotations

import re
import sqlite3
import time
from contextlib import closing

import sqlglot
from sqlglot import exp

from . import llm, ontology
from .core import connect, data_dir

DENY_FUNCS = {"load_extension", "readfile", "writefile", "set_config", "pg_read_file", "dblink", "randomblob", "sqlite_version"}
MAX_LIMIT = 200


class SQLRejected(ValueError):
    pass


def profile_inclusion_deps(threshold: float = 0.95) -> list[tuple[str, str, float]]:
    """Find implicit FKs: distinct(A) ⊂ distinct(B) with overlap >= threshold."""
    with connect("legacy") as c:
        cols = [(t, r[1]) for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'")
                for r in c.execute(f"PRAGMA table_info({t})") if re.search(r"(id|ref|sn|_no)$", r[1])]
        vals = {tc: {v for (v,) in c.execute(f"SELECT DISTINCT {tc[1]} FROM {tc[0]} WHERE {tc[1]} IS NOT NULL")}
                for tc in cols}
    out = []
    for a, va in vals.items():
        for b, vb in vals.items():
            if a != b and va and len(vb) >= len(va):
                ov = len(va & vb) / len(va)
                if ov >= threshold and a[0] != b[0]:
                    out.append((f"{a[0]}.{a[1]}", f"{b[0]}.{b[1]}", round(ov, 3)))
    return out


def validate(sql: str) -> str:
    try:
        trees = sqlglot.parse(sql, read="sqlite")
    except sqlglot.errors.ParseError as e:
        raise SQLRejected(f"parse error: {e}") from e
    if len(trees) != 1 or not isinstance(trees[0], exp.Select):
        raise SQLRejected("only a single SELECT is allowed")
    tree = trees[0]
    allowed = set(ontology.load()["canon_views"])
    ctes = {c.alias_or_name for c in tree.find_all(exp.CTE)}
    for t in tree.find_all(exp.Table):
        if t.name not in allowed | ctes or t.db:
            raise SQLRejected(f"relation not allowed: {t.sql()}")
    exposed = {c for v in allowed for c in ontology.exposed_columns(v)}
    blocked = {c for v in allowed for c in ontology.load()["canon_views"][v]["columns"]} - exposed
    blocked |= {c for cols in ontology.load()["columns"].values() for c, s in cols.items()
                if s["classification"] in ontology.BLOCKED}
    aliases = {a.alias for a in tree.find_all(exp.Alias)}
    if aliases & blocked:  # aliasing to a sensitive name would let a later reference slip past the column check
        raise SQLRejected(f"alias not allowed: {sorted(aliases & blocked)[0]}")
    for col in tree.find_all(exp.Column):
        if col.name not in exposed | aliases:
            raise SQLRejected(f"column not allowed: {col.name}")
    for f in tree.find_all(exp.Func):
        name = (f.sql_name() if not isinstance(f, exp.Anonymous) else f.name).lower()
        if name in DENY_FUNCS:
            raise SQLRejected(f"function not allowed: {name}")
    for clause in (*tree.find_all(exp.Limit), *tree.find_all(exp.Offset)):
        value = clause.expression
        if not isinstance(value, exp.Literal) or value.is_string or not value.this.isdigit():
            raise SQLRejected("limit and offset must be nonnegative integer literals")
    lim = tree.args.get("limit")
    if lim is None or int(lim.expression.this) > MAX_LIMIT:
        tree = tree.limit(MAX_LIMIT)
    return tree.sql(dialect="sqlite")


TEMPLATES = [
    (r"how many (active|suspended|pending|terminated) customers.*?(\d{5})",
     "SELECT COUNT(*) AS n FROM canon_customer WHERE status = '{0}' AND service_zip = '{1}'"),
    (r"how many (active|suspended|pending|terminated) customers",
     "SELECT COUNT(*) AS n FROM canon_customer WHERE status = '{0}'"),
    (r"how many customers.*?(\d{5})", "SELECT COUNT(*) AS n FROM canon_customer WHERE service_zip = '{0}'"),
    (r"(?:which|list) devices.*?model ([A-Z0-9-]+)",
     "SELECT cpe_sn, customer_id, firmware FROM canon_resource WHERE model = '{0}'"),
    (r"how many devices (?:per|by) model", "SELECT model, COUNT(*) AS n FROM canon_resource GROUP BY model ORDER BY model"),
    (r"(?:devices|cpes?) on (PON-\d{2}-\d{2})", "SELECT cpe_sn, customer_id FROM canon_resource WHERE pon_port_id = '{0}'"),
    (r"open work orders", "SELECT work_order_id, customer_id, state FROM canon_work_order"
                          " WHERE state IN ('DISPATCHED','IN_PROGRESS')"),
]


def schema_context() -> str:
    return "\n".join(f"{v}({', '.join(ontology.exposed_columns(v))})" for v in ontology.load()["canon_views"])


def generate(question: str, error: str | None = None) -> str:
    q = question.strip()
    for pat, tpl in TEMPLATES:
        m = re.search(pat, q, re.IGNORECASE)
        if m:
            return tpl.format(*[g.replace("'", "") for g in m.groups()])
    out = llm.generate(
        f"Write one SQLite SELECT answering the question using ONLY these views:\n{schema_context()}\n"
        f"Question: {q}\n{'Previous error: ' + error if error else ''}\nReturn only SQL.")
    if not out:
        raise SQLRejected("no SQL could be generated for this question")
    return out.strip().strip("`").removeprefix("sql").strip()


def answer(question: str, scope_subscribers: list[str] | None, timeout_s: float = 2.0) -> dict:
    err = None
    for _ in range(3):  # initial + 2 self-repairs
        try:
            sql = generate(question, err)
            safe = validate(sql)
            with closing(sqlite3.connect(":memory:", uri=True)) as conn:
                conn.execute("ATTACH DATABASE ? AS legacy", ((data_dir() / "legacy.db").as_uri() + "?mode=ro",))
                ontology.create_scoped_views(conn, scope_subscribers)
                conn.execute("PRAGMA query_only=ON")
                conn.execute("EXPLAIN QUERY PLAN " + safe)
                deadline = time.monotonic() + timeout_s
                conn.set_progress_handler(lambda d=deadline: int(time.monotonic() > d), 1000)
                cur = conn.execute(safe)
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, r)) for r in cur.fetchmany(MAX_LIMIT)]
            return {"sql": safe, "rows": rows}
        except (SQLRejected, sqlite3.Error) as e:
            err = str(e)
            if isinstance(e, SQLRejected) and "no SQL" in err:
                break
    raise SQLRejected(err or "failed")
