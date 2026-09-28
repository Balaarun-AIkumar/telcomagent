# Design decisions

## 1. One orchestrator and one default app

A constrained intent router plus explicit Python plans makes the authorization path inspectable. We removed automatic outage writes and the network A2A hop from the default path. The legacy HTTP contracts remain in-process mocks. MCP, A2A, ADK, Neo4j and cloud telemetry are optional adapters, not prerequisites.

## 2. Code owns permissions

A language model can select an intent but cannot grant access. Tool schemas, role checks, exact object relationships and live user attributes are enforced by trusted code. Permit, if configured, adds an external decision; it does not replace local expiry/revocation guards. There is some policy duplication, deliberately tested to avoid unsafe fallback.

## 3. Secrets leave chat entirely

A successful credential request yields a short-lived, user-bound reference. A separate endpoint atomically redeems it, rechecks policy and returns the synthetic password directly to the UI. Reset/reboot use a separate action-bound confirmation token. This is stronger than relying on prompt instructions or regex redaction.

## 4. SQLite keeps the review small

The core uses two local databases and FTS5. Canonical views expose safe columns and exact customer scopes to SELECT-only SQL. PostgreSQL DDL in `sql/` is a reference design, not the running backend. Moving to Postgres would require migrations and parity tests; there is no claim of production parity today.

## 5. Evidence before prose

Procedure retrieval returns cited sections; data tools return structured facts. Responses are formatted deterministically. Gemini improves routing and unsupported SQL generation, while facts and authorization remain outside the model. This trades conversational flexibility for reproducibility and a smaller security surface.

## 6. Bounded, user-scoped memory

Short-term state holds the last subject and 20 turn summaries. Cross-session episodes are opt-in and separately filtered by user plus current subscriber authorization. Expiry is enforced on reads even before records are purged.

## 7. Optional integrations earn their place

Permit centralizes policy management; Langfuse helps inspect traces; Neo4j serves two topology queries; MCP exposes the guarded tools to a client; A2A illustrates audience/scope-bound delegation and untrusted vendor output. They are useful extension points, but none justifies a default multi-service deployment for this demo.

## 8. Operational limits are explicit

Single-process rate limiting and task buffers, synthetic identity, simulated step-up and SQLite audit are prototype choices. Docker runs nonroot and excludes secrets from its build context. Production identity, secret management, distributed controls and realistic evaluation data are future work, not features implied by installing more frameworks.
