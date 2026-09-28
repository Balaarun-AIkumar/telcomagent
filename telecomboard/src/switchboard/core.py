"""Settings, clock and SQLite access (local stand-ins for Postgres legacy/platform DBs)."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

_clock_offset = 0.0


def now() -> float:
    return time.time() + _clock_offset


def advance_clock(seconds: float) -> None:
    """Test/demo helper to simulate 'next day' without sleeping."""
    global _clock_offset
    _clock_offset += seconds


def data_dir() -> Path:
    p = Path(os.getenv("SB_DATA_DIR", Path.cwd() / ".sbdata"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


class Connection(sqlite3.Connection):
    """SQLite's default context manager commits but does not close the handle."""

    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect(name: str = "platform") -> sqlite3.Connection:
    """name: 'platform' or 'legacy'. The platform connection ATTACHes legacy for cross-DB transactions."""
    if name not in {"platform", "legacy"}:
        raise ValueError("unknown database")
    conn = sqlite3.connect(data_dir() / f"{name}.db", timeout=10, check_same_thread=False, factory=Connection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if name == "platform":
        conn.execute("ATTACH DATABASE ? AS legacy", (str(data_dir() / "legacy.db"),))
    return conn


PLATFORM_DDL = """
CREATE TABLE IF NOT EXISTS app_user(user_id TEXT PRIMARY KEY, display TEXT, role TEXT NOT NULL, tenant TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS app_user_attr(user_id TEXT PRIMARY KEY, attrs TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS idg_edge(
  id INTEGER PRIMARY KEY, src_type TEXT NOT NULL, src_id TEXT NOT NULL, rel TEXT NOT NULL,
  dst_type TEXT NOT NULL, dst_id TEXT NOT NULL, valid_from REAL NOT NULL, valid_to REAL);
CREATE TABLE IF NOT EXISTS idg_outbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op TEXT NOT NULL CHECK (op IN ('upsert_tuple','delete_tuple','set_user_attr')),
  payload TEXT NOT NULL, created_at REAL NOT NULL, published_at REAL);
CREATE INDEX IF NOT EXISTS outbox_pending ON idg_outbox(id) WHERE published_at IS NULL;
CREATE TABLE IF NOT EXISTS pdp_tuple(subject TEXT, relation TEXT, object TEXT, expires_at REAL,
  PRIMARY KEY(subject, relation, object));
CREATE TABLE IF NOT EXISTS pdp_user_attr(user_id TEXT PRIMARY KEY, attrs TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reveal_grant(
  grant_hash BLOB PRIMARY KEY, grantee_id TEXT NOT NULL, cpe_sn TEXT NOT NULL, work_order TEXT NOT NULL,
  trace_id TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL,
  CHECK (expires_at <= created_at + 300));
CREATE TABLE IF NOT EXISTS action_confirmation(
  ref_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, action TEXT NOT NULL, args TEXT NOT NULL,
  expires_at REAL NOT NULL, used_at REAL);
CREATE TABLE IF NOT EXISTS audit_policy_decision(
  id INTEGER PRIMARY KEY AUTOINCREMENT, decided_at REAL NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
  resource TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','step_up','break_glass')),
  reason TEXT NOT NULL, trace_id TEXT, prev_hash BLOB, row_hash BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_policy_decision
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_policy_decision
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS kb_document(doc_id TEXT PRIMARY KEY, family TEXT, title TEXT, revision INTEGER,
  effective_date TEXT, vendor TEXT, model TEXT, firmware_range TEXT, classification TEXT, source_kind TEXT);
CREATE TABLE IF NOT EXISTS kb_chunk(chunk_id INTEGER PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES kb_document(doc_id),
  parent_id INTEGER, section_path TEXT NOT NULL, content TEXT NOT NULL, classification TEXT NOT NULL,
  quarantined INTEGER NOT NULL DEFAULT 0, injection_score REAL, ocr_confidence REAL, page INTEGER, embedding TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(content, content='', tokenize='porter unicode61');
CREATE TABLE IF NOT EXISTS memory_episode(episode_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, subject_ref TEXT,
  summary TEXT NOT NULL, embedding TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  CHECK (expires_at > created_at));
CREATE TABLE IF NOT EXISTS session_state(session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, state TEXT NOT NULL,
  updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS catalog_column_semantics(tbl TEXT, col TEXT, meaning TEXT, ontology_ref TEXT,
  classification TEXT, status TEXT CHECK (status IN ('proposed','approved','rejected')), confidence REAL,
  evidence TEXT, PRIMARY KEY (tbl, col));
CREATE TABLE IF NOT EXISTS catalog_verified_query(id INTEGER PRIMARY KEY, question TEXT, sql TEXT);
"""


def init_platform() -> None:
    with connect("platform") as c:
        c.executescript(PLATFORM_DDL)
        # Upgrade existing local demo databases: the former PDP attribute table is
        # the only available seed for the new app-owned current-facts table.
        c.execute("INSERT OR IGNORE INTO app_user_attr(user_id, attrs) "
                  "SELECT user_id, attrs FROM pdp_user_attr")
