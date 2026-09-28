-- Cloud-profile platform schema (Postgres 16 + pgvector). Local mode uses the SQLite equivalent in core.py.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE SCHEMA IF NOT EXISTS kb; CREATE SCHEMA IF NOT EXISTS memory; CREATE SCHEMA IF NOT EXISTS idg;
CREATE SCHEMA IF NOT EXISTS secrets; CREATE SCHEMA IF NOT EXISTS audit; CREATE SCHEMA IF NOT EXISTS catalog;

CREATE TABLE kb.document (doc_id text PRIMARY KEY, family text, title text, revision int, effective_date date,
  vendor text, model text, firmware_range text, classification text NOT NULL, source_kind text);
CREATE TABLE kb.chunk (
  chunk_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  doc_id text NOT NULL REFERENCES kb.document(doc_id),
  parent_id bigint REFERENCES kb.chunk(chunk_id),
  section_path text NOT NULL, content text NOT NULL, classification text NOT NULL,
  quarantined boolean NOT NULL DEFAULT false, injection_score real, ocr_confidence real, page int,
  embedding vector(768),
  tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED);
CREATE INDEX ON kb.chunk USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON kb.chunk USING gin (tsv);

CREATE TABLE idg.edge (
  src_type text NOT NULL, src_id text NOT NULL, rel text NOT NULL, dst_type text NOT NULL, dst_id text NOT NULL,
  valid_during tstzrange NOT NULL DEFAULT tstzrange(now(), NULL),
  EXCLUDE USING gist (src_type WITH =, src_id WITH =, rel WITH =, dst_type WITH =, dst_id WITH =, valid_during WITH &&));
CREATE TABLE idg.outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  op text NOT NULL CHECK (op IN ('upsert_tuple', 'delete_tuple', 'set_user_attr')),
  payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz);
CREATE INDEX outbox_pending ON idg.outbox (id) WHERE published_at IS NULL;

CREATE TABLE secrets.reveal_grant (
  grant_hash bytea PRIMARY KEY, grantee_id text NOT NULL, cpe_sn text NOT NULL, work_order text NOT NULL,
  trace_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  used_at timestamptz, CHECK (expires_at <= created_at + interval '5 minutes'));

CREATE TABLE audit.policy_decision (
  id bigint GENERATED ALWAYS AS IDENTITY, decided_at timestamptz NOT NULL DEFAULT now(),
  actor_id text NOT NULL, action text NOT NULL, resource text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny', 'step_up', 'break_glass')),
  reason jsonb NOT NULL, trace_id text, prev_hash bytea, row_hash bytea NOT NULL,
  PRIMARY KEY (decided_at, id)) PARTITION BY RANGE (decided_at);
CREATE TABLE audit.policy_decision_default PARTITION OF audit.policy_decision DEFAULT;

CREATE TABLE memory.episode (
  episode_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id text NOT NULL, subject_ref text,
  summary text NOT NULL, embedding vector(768) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL, CHECK (expires_at > created_at));
CREATE INDEX ON memory.episode USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON memory.episode (user_id, subject_ref, created_at DESC);

CREATE TABLE catalog.column_semantics (tbl text, col text, meaning text, ontology_ref text, classification text,
  status text CHECK (status IN ('proposed', 'approved', 'rejected')), confidence real, evidence text,
  PRIMARY KEY (tbl, col));

DO $$ BEGIN CREATE ROLE app_writer NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT INSERT, SELECT ON audit.policy_decision TO app_writer;
REVOKE UPDATE, DELETE ON audit.policy_decision FROM app_writer;
