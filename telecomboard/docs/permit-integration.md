# Permit.io local integration

## Start the development PDP

The app's `PermitPDP` uses `PERMIT_API_KEY` to select the Permit adapter and defaults `PERMIT_PDP_URL` to `http://localhost:7766`. The local container is required for Permit ABAC policies. The managed Cloud PDP does not evaluate ABAC.

1. In the repository root, copy `.env.example` to `.env`.
2. In the Permit dashboard, select **Default Project → Development**, open the user menu, and copy the **Environment Key**. Put it on the `PERMIT_API_KEY=` line in `.env`. Do not put the value in source files or commit `.env`.
3. Keep `PERMIT_PDP_URL=http://localhost:7766` in `.env`.
4. In a PowerShell terminal at the repository root, start the container:

   ```powershell
   docker compose --env-file .env -f compose.permit.yml up -d
   ```

   Compose reads `PERMIT_API_KEY` from `.env` and passes it to the container as `PDP_API_KEY`. The PDP listens on container port 7000, mapped only to `127.0.0.1:7766` on this computer. The app launcher separately loads `.env` and passes `PERMIT_API_KEY` to the SDK.

5. In a second PowerShell terminal, check the health endpoint:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:7766/health
   ```

   Permit documents a healthy response as HTTP 200 with `status: ok`. Then start the app in that terminal:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ```

6. Because the PDP runs detached, stop it with `docker compose -f compose.permit.yml stop`. The container image uses `latest` for local setup; pin a reviewed release tag before relying on this in a production deployment.

The same Development environment key is used by the app SDK and the container. Do not paste it into chat, source code, shell history, or screenshots. `.env` is excluded by `.gitignore`.

## Which checks use attributes?

The current local policy engine (`src/switchboard/policy.py`) checks the following values:

| Check | Values used | Could model it as ReBAC? |
|---|---|---|
| Document access | Resource `classification` is converted to an ordinal and compared with `ROLE_CLEARANCE` (public < internal < confidential/vendor_nda < restricted). | Yes, by making classification a related resource/group and assigning users/roles access to that group. The app would need to maintain those classification tuples whenever documents are ingested or reclassified. Today it is an actual resource attribute and the retrieval query filters on it. |
| Credential reveal | User `on_shift`, `device_trust == managed`, contractor `cert_valid`, recent authentication (`step_up_age_s < 300`), plus assignment or supervisor break-glass. | Assignment and break-glass are already relationship checks. Shift, trust, certificate, and recent authentication are request/user facts. They could be converted into short-lived eligibility relationships only if a trusted app component validates them, creates/revokes the tuples, and enforces expiry. That moves the attribute evaluation into the tuple issuer; it is not a simpler or safer conversion for this app. |
| Memory recall | Episode `subject_ref` is re-authorized through the referenced subscriber's `read_profile` permission; the SQL query also scopes episodes to the current user. | Yes, as a direct `memory_episode` to `subscriber` relation, while retaining per-user ownership and expiry filtering in the data layer. Current implementation carries `subject_ref` as an attribute for the PDP probe. |

The rest of the checks are role grants (RBAC) or graph relationships (ReBAC). Technician assignment follows `user → work_order → subscriber → cpe_device`; break-glass is a time-limited relationship created only after the gateway verifies two distinct supervisor identities and a justification.

**Conclusion:** the policy semantics can be represented without Permit ABAC in theory, but only by moving classification, device-context, and step-up evaluation into trusted application code that mints and revokes Permit relationships. In the existing implementation these are ABAC checks. The container PDP is therefore the direct-fit option if Permit is to evaluate the ABAC policy itself.

## Adapter behavior and synchronization

The adapter changes address the three application-side gaps:

1. **Live attributes on every check.** `LocalPDP.user_attrs()` now reads the app-owned `app_user_attr` row on each check. `idg.set_user_attr()` updates that source-of-truth row transactionally before queuing sync. `PermitPDP.check()` sends those latest values in the Permit `user.attributes` object on the same call; it also sends request context as JIT user attributes and `context`, and resource attributes (including document `classification`) in the resource object. In particular, the gateway computes `step_up_age_s = now() - auth_time` at reveal redemption, and the value goes to Permit on that check. `on_shift`, `device_trust`, and `cert_valid` are also read from the latest app-owned row each time, not from Permit's stored user profile. Updating shift/device/certificate state must go through `idg.set_user_attr()` so the source row and outbox change together.

   The adapter first runs the local policy as an independent guard, then requires Permit to allow exact object checks. Permit drift therefore cannot turn a local denial into an allow; a Permit denial or request error also fails closed. Relationship-only wildcard discovery probes remain local-only; broad role-authorized wildcard reads also require Permit. Individual discovered objects are checked separately. For memory episodes with a subject, Permit checks `read_profile` on that subscriber. Episodes without a subject remain constrained by the existing owner-scoped SQL query.

   Creating a step-up challenge is a non-disclosing preflight: it checks role, current shift/device/certificate state, and the active assignment or break-glass link, but does not check the Permit credential-reveal action. The challenge contains no credential. At redemption, the gateway computes the fresh authentication age and both local policy and Permit must approve the actual reveal. This preserves the `<300s` requirement without blocking the challenge needed to satisfy it.

2. **Tuple expiration.** Permit relationship/instance-role assignment APIs do not expose tuple TTL in the documented create payload. The adapter keeps the expiration timestamp in its app-owned tuple table. Local policy filters an expired tuple immediately; a daemon reaper scans every second and unassigns the corresponding Permit instance role, retrying if Permit is unavailable. Until remote revocation succeeds, local authorization still denies the expired tuple. This applies to the 15-minute `break_glass` instance role; work-order assignment relationships have no time expiry and are explicitly deleted when their source edge closes. A live Development check created a temporary break-glass grant with an expiry one second in the past, confirmed the local tuple was removed, and confirmed Permit denied reveal after remote revocation.

3. **User/role/relationship sync.** The app database is the source of truth. On each Permit-mode gateway startup, the app queues a full reconciliation of current users, active graph edges, and unexpired break-glass tuples. Later user/role/attribute and edge changes are enqueued transactionally through `idg.set_user_attr()`, `idg.set_user_role()`, and `idg.add_edge()`/`idg.close_edge()`. The worker retries pending events once per second; failures remain pending. Resource-to-resource relationships are sent through Permit's bulk tuple endpoint in chunks of 500; user instance-role assignments remain individual calls. The app's `serves` edge maps to Permit’s `parent` relation, and `owns` maps to Permit’s `owner` relation; local tuple names remain unchanged. For an unassigned subscriber/device without a work order, sync uses the sole non-contractor application tenant; it fails closed if that tenant is ambiguous. Exact checks require both the local guard and Permit to allow, so drift denies rather than opens access. A restart replays current app state to repair missing facts in Development.

### Development policy state and tests

The Development project now has these saved relationship and ABAC schema items:

- Resource relations: `work_order` parent of `subscriber`, and `subscriber` owner of `cpe_device`.
- Derived roles: `work_order#assignee` derives `subscriber#assignee` over the first relation; `subscriber#assignee` derives `cpe_device#assignee` over the second. A work-order assignee therefore gets related subscriber/device scope without per-device grants.
- User attributes: `on_shift` (boolean), `device_trust` (string enum `managed`/`unmanaged`), `cert_valid` (boolean), `step_up_age_s` (number), `clearance_level` (number), `is_contractor` (boolean), and `has_device_link` (boolean).
- `Credential reveal eligible` user set: requires `on_shift == true`, `device_trust == "managed"`, `step_up_age_s < 300`, and `has_device_link == true`; it additionally requires `cert_valid == true` only when `is_contractor == true`.
- The `Document within user clearance` resource set compares `resource.classification_level <= user.clearance_level`. The adapter emits numeric ranks (`public=0`, `internal=1`, `vendor_nda/confidential=2`, `restricted=3`). The condition set was saved successfully in Development.
- The separate `cpe_device#break_glass` role remains limited to `reveal_credential`; the Supervisor role has no broad `reveal_credential` permission.

The offline adapter tests in `tests/test_permit_adapter.py` cover:

- current `on_shift` and document `classification` included in a JIT check;
- an on-shift change to false denied before Permit is called;
- fresh `step_up_age_s` forwarded and a Permit-side deny remaining a deny;
- a break-glass tuple whose expiry is one second in the past denied and its Permit instance role unassigned;
- user/tenant role sync plus user-to-work-order and work-order-to-subscriber sync payloads;
- startup reconciliation queuing current users and active graph edges.

The app-level memory scoping remains `WHERE user_id=?` in `memory.recall()` before the authorization check; Permit does not choose which rows the query fetches.

The offline relationship-sync test asserts the `serves` → Permit `parent` mapping. The focused Permit adapter file has 12 passing tests, including the one-second-past-expiry revocation case, orphan-tenant handling, batch relation mapping, and the preflight-versus-redemption check. The full offline suite passes all 82 tests; live checks below cover Development PDP compatibility.

### Remaining steps

The saved schemas, conditions, derivations, and policy matrix grants were verified in Development. `Credential reveal eligible` has `cpe_device.reveal_credential`; the seven application roles have `read` on `Document within user clearance`, whose ordinal condition filters documents by each role's clearance. The existing `cpe_device#break_glass` instance role remains the other reveal grant; the Supervisor role's broad reveal cell remains unchecked.

With the user's Development key kept in the ignored `.env`, the local PDP health endpoint returned `status: ok`. The app reconciled 2,214 queued records with no pending outbox entries. A live Permit check allowed restricted-document access for `priya` (`noc_engineer`) and denied it for `raj` (`csr_tier1`). The live one-second-past-expiry break-glass test revoked the remote instance role and Permit denied credential reveal afterward.

## Repository review hardening

Closing an assignment now deletes the local replicated tuple in the same transaction, before remote outbox delivery. SQL uses exact assigned subscriber IDs rather than postcodes. Tests cover immediate revocation without synchronization, expired tuples, and invalid/negative/non-finite step-up ages. Confirmation tokens for reset/reboot are user/action/argument-bound and single-use.

## Allowed-scenario repair (28 September 2026)

Two separate causes were found live: Docker Desktop was stopped, and the derived instance roles existed without read permissions. Restoring the PDP fixed broad role reads and document access. Adding the following missing Development instance-level permissions fixed assigned-user lookup and follow-up:

| Resource instance role | Required read permissions |
|---|---|
| subscriber#assignee | read_profile, read_pii |
| cpe_device#assignee | read_status, read_config |
| work_order#assignee | read |

The existing derivations remain work_order#assignee -> subscriber#assignee through parent, then subscriber#assignee -> cpe_device#assignee through owner. No broad credential reveal grant was added. The app's local guard still narrows permissions by persona (including contractor PII restrictions), live attributes and relationship expiry. Permit must not be used as a replacement for that guard.

Startup now checks the configured PDP's health and exits with setup instructions if unavailable. Mid-session outages return POLICY_UNAVAILABLE with an explicit service-outage message; subscriber and procedure tools no longer misreport them as absent data or a role denial. There is no automatic authorization fallback.

For a deliberately local demo without cloud dependencies, run `powershell -ExecutionPolicy Bypass -File .\start.ps1 -Offline`. This choice is explicit; the standard launcher continues to use configured Permit.

Live verification passed: Maya reveal/redemption/reuse prevention and follow-up; Priya outage; Raj SQL and confirmed reset; Maya procedure lookup; ten expected denials; injection blocking; self-approved break-glass rejection. Automated suite: 119 passed.
