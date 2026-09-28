# Security boundaries and remaining risks

## Protected assets

Synthetic subscriber records, device Wi-Fi credentials, assignment relationships, reset/reboot actions, document classifications, memory and decision audit records.

## Boundaries enforced in code

- JWT signature/audience verification and current directory role lookup.
- Typed tool inputs and central action/resource checks.
- Per-object authorization and exact subscriber IDs in SQL views.
- Read-only attached SQL source, SELECT AST checks, bounded rows and execution.
- Live shift/trust/certification checks and recent authentication for reveal.
- Expiry-aware relationship reads and immediate local revocation.
- Single-use actor-bound reveal and action-confirmation references.
- User-scoped memory queries followed by read-time authorization.
- Classification/latest-revision filters and poisoned-document quarantine.
- Receiver-side scope and authorization for optional A2A calls; task ownership checks.
- No credential values in chat/model context, telemetry attributes or HTTP cassettes.

## Defense in depth

Injection detection and output scrubbing are heuristics. They can miss novel attacks and must not replace policy checks. Retrieved documents and vendor text remain untrusted data. Application logs contain metadata, but local demo debug tools can show synthetic questions and subject identifiers.

## Assumptions and limits

Use synthetic data and localhost only. Persona selection and recent-auth simulation are not enterprise authentication/MFA. Signing/encryption keys live in the local data directory. Anyone controlling the host or database has stronger privileges than this demo's application roles. Internal broad-reader roles are organization-wide in the synthetic model; redesign tenant ownership before onboarding multiple real organizations.

Audit triggers and hashes detect ordinary modification, not a privileged administrator rewriting the complete store. In-memory rate limiting is not distributed. Optional remote topology is a snapshot and may be stale. An upstream timeout can complete after the orchestrator stops scheduling work; retries are restricted to reads or idempotency-keyed HTTP requests. Do not publish development token endpoints.

## Public repository hygiene

Keep `.env`, `.sbdata`, signing keys and credential downloads out of Git. `.dockerignore` excludes secrets from build context; runtime environment variables are still readable by operators with container access. Before publishing, inspect staged files and run a secret scanner. Publishing source does not deploy an application, and Docker is not a secret vault.
