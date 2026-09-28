# Review results - 28 September 2026

## Scope

Reviewed the Python source, API and browser UI, policy and sync adapters, tests/evaluation fixtures, Docker setup and documentation. The architecture now presents one core app and optional integration adapters. The existing local `.env` was preserved; no credentials were inserted into source.

## Changes that matter

| Issue | Improvement | Evidence |
|---|---|---|
| Technician SQL scope used a postcode | Exact authorized subscriber IDs, including expiry checks | Regression proves one assigned customer versus 24 in the same postcode |
| Chat text could approve a reset | Hashed single-use confirmation bound to actor/action/arguments/expiry | Wrong actor/action, reuse, expiry and role-change tests |
| Outage diagnosis automatically wrote operational records | Read-only plan for topology, device status and procedures | Updated intentional trace fixture and end-to-end smoke |
| Old token could retain a revoked role | Reload current directory role on token verification | Role-revocation regression |
| Local revocation waited for sync | Remove local tuple in the relationship-closing transaction | Denial before remote sync test |
| Tool inputs and upstream failures were weakly handled | Pydantic schemas, identifier patterns and safe outward errors | Unknown/malformed tool and upstream-failure cases |
| Step-up age accepted invalid numbers | Finite age in [0,300) required | Negative, non-finite, string and boundary tests |
| Optional A2A trusted audience alone | Receiver scope and policy checks, actor/tenant task ownership | Protocol tests and denied topology cases |
| SQL limits and connections were fragile | Literal bounds, read-only attach, query-only mode, timeout, reliable close | Invalid-limit and execution tests |
| Procedure reingestion duplicated data | Replace old chunks and FTS entries; restrict latest revision | Idempotent reingestion and retrieval tests |
| Unrelated questions could retrieve arbitrary hash-vector hits | Require lexical evidence | No-match regression |
| Session keys and history were weakly bounded | User/session keys, 20-turn summaries; long-term memory opt-in | Session isolation and existing memory reauthorization tests |
| Password endpoint could enter a recording | Never record/replay the secret endpoint | Cassette regression |
| Default architecture implied many agents/services | One constrained router and explicit plans; one-app Compose | Docker image and HTTP smoke |
| Model use was hard to demonstrate | Validated optional Gemini intent classifier and routing_source | Mocked semantic routing/fallback tests |
| Telemetry could export raw question attributes | Raw input only in local debug buffer; actual OTel trace IDs | Existing tracing tests; no new cloud export required |
| Public-repo hygiene was incomplete | Broader ignore rules, empty env example, local scanner, clean ZIP | Publication audit below |

## Verification actually performed

- Final pytest run: **115 passed** (67 seconds on this machine).
- Ruff: **all checks passed**, including source, tests, evals, scripts and conftest.
- Docker image `switchboard:review` built successfully with the core dependencies.
- Isolated localhost container on port 18080 passed HTTP checks for health, authorized reveal, denied CSR, single-use reveal, bound confirmation, exact SQL scope, read-only outage and cited procedures. No cloud keys were passed.
- Browser showed a cited ONT procedure and a reset confirmation card. A later browser reconnection was blocked by the browser tool's URL policy; no workaround was attempted. HTTP and automated flow verification completed independently before that block.
- On the final continuation Docker Desktop was stopped, so the earlier successful smoke run was not repeated and the temporary container could not be queried for cleanup. When Docker is running, `docker stop switchboard-review-smoke` removes the temporary `--rm` container if it still exists.
- PDF: 19 pages, 5,081 words; all rendered pages inspected, no blank pages or clipped content found.
- Live Gemini accuracy, fresh cloud integration calls, load testing and public deployment were **not** performed in this review. Existing cloud integrations were preserved. Offline/mocked tests do not imply live provider accuracy.

## Publication audit

The Git root is the parent `Downloads/RAG` folder, which contains unrelated personal files. It has **no commits, no remote and no staged changes**. Do not upload that parent folder. Only the clean project archive is intended for manual upload.

`check_secrets.py` scans the project Git candidates using common token patterns and exact configured values from `.env` (including derived Langfuse Basic auth) without printing values. The final scan covered 82 project upload candidates; no findings were detected. `.env`, databases, signing keys, temporary test data and local environments are excluded. The scanner is a focused check, not a guarantee against every possible secret format or disclosures outside this local repository.

The source ZIP is generated from checked project candidates and its entries are rechecked before delivery. Do not substitute an older ZIP from the parent folder, which has not been verified.

## Remaining production work

Real OIDC/MFA, explicit multi-organization tenancy, secret management, HTTPS, protected centralized audit, distributed rate limiting, larger language/retrieval evaluations and load tests. The default demo is deliberately local with synthetic data. No Kubernetes or public service was added.

## Follow-up live repair

The later user-reported scenario failures were reproduced against the configured app. Docker was stopped, making Permit unavailable; derived assignee roles also lacked read grants. The PDP was restored and the missing instance-level read permissions were repaired. All 18 live checks passed against real Permit, including the allowed flows and expected blocks; no secret values were printed. The expanded suite passed 119 tests and lint passed. The gateway is running again on localhost:8000.

UI examples are now split into Allowed scenarios and Blocked scenarios; S2 and S4 are correctly labelled as expected refusals. Startup checks PDP health, and runtime outages produce service-unavailable explanations rather than misleading authorization/empty-document messages. The GitHub ZIP and upload folder were refreshed with these changes.
