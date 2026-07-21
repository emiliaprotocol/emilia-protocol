# Strix / Hostile Audit Remediation — 2026-07-18

> **Status: active retest — not a closure memo.** The latest full-stack Strix report records
> **14 issues: 1 critical, 6 high, 5 medium, and 2 low**. Strix is currently running against the
> target surface and has reported additional findings. The branch evidence below describes
> changes and tests observed in this integration tree; it does not establish production
> deployment, live schema application, or closure of the active Strix report. Update this
> document only after each finding is independently triaged, fixed, and retested.

## Scope and evidence boundary

The earlier Strix completion email reported 10 findings: 7 high, 1 medium, and 2 low. The latest full-stack report supplied for this review supersedes that summary with 14 findings: 1 critical, 6 high, 5 medium, and 2 low. The report says repository-level fixes were applied and targeted tests/builds passed, but production still requires deployment and live retesting. This document records branch evidence, not a claim that every report item is closed.

The hostile-code audit v3 was available as a source report and was checked against the integration tree.

## Remediations present on the integration branch

| Area | Change | Evidence |
| --- | --- | --- |
| Action Escrow approval tampering | Release replays the persisted binding, funding statement, milestone evidence, and each release approval before invoking a provider. | `4937ae5`; 128 focused Node/Vitest escrow and release-lock tests passed, including tampered approval and recomputed-summary regressions. |
| Release Lock participant evidence | Unscoped invitation sessions fail closed. Scoped evidence is a redacted projection without contacts, credentials, counterparty decisions, Action Check internals, or effect/transaction identifiers. | `7cd3a5d`; 158 release-lock tests and 78 targeted tests passed in the worker lane. |
| Route authorization/write boundary | Audited handshake, webhook, dispute, and key-rotation routes use the guarded client and explicit actor projections; no API route may import the raw service client or inspect `auth.entity`. | `49f4466` plus the current `check:write-discipline` gate; 379 route-family tests passed in this pass. |
| SSO secrets | Production requires explicit `SSO_STATE_SECRET` and `SSO_SESSION_SECRET`; no service-role-derived or source-predictable fallback remains. | `ea61dea`; 23 focused SSO/env/canonical tests passed. |
| Canonicalization | WebAuthn now uses the shared canonicalizer and rejects out-of-profile values; parity vectors cover the portable verifier. | `8948eb2`; 39 WebAuthn/canonical tests passed. |
| Mobile signer dependencies | Patched transitive dependencies are pinned; the secure-app audit is clean and Expo checks pass. | `118aceb`; production dependency audit reported 0 high vulnerabilities, secure-app tests passed, Expo Doctor 18/18. |
| Database Fortress controls | RLS, public table/column ACL, Release Lock RPC-only access, and live catalog contract checks were added. | `484f99e`; static migration audit reported 162 invariants passed; PostgreSQL 17.9 replay passed. |
| Logger and runtime configuration | Logger bootstrap settings now come only from `lib/env.js`; environment access is no longer duplicated in `lib/logger.js`. | Current `rg process.env lib/logger.js` is empty; logger and auth regression tests pass. |
| Service-client isolation | `getServiceClient()` creates a non-persistent client per call with session persistence disabled; no process-scoped singleton remains. | `tests/service-client-isolation.test.ts`; 91 focused security tests passed. |
| Durable rate-limit posture | Sensitive routes use named durable-required categories; unknown `write` categories were removed, and `protocol_read` is explicit instead of silently falling back to generic reads. | `lib/rate-limit.js`; production without Upstash fails closed for sensitive categories. |
| Async Gate provider resolution | `guard()` awaits selector, receipt, observed-action, admissibility, and reliance-packet providers; an async selector without a receipt now produces `receipt_required` and never invokes the effect. | `packages/gate/index.js`; async-provider and fail-closed regressions in `packages/gate/gate.test.js` pass. |
| Approver enrollment authorization | WebAuthn registration issuance and completion require the explicit `approver.enroll` capability or the documented `admin` super-capability; tenant binding remains mandatory. | `lib/approver-enrollment-auth.js`; both registration routes and the non-admin regression tests pass. |
| Public Action Escrow surface | Website content now explains the action-bound approval flow, exact outcomes, refusal codes, and simulated-provider/custody boundary. | `4d22394`; focused copy tests and Next build passed in the worker lane. |

## Latest full-stack Strix findings — branch disposition

The following controls are now present in this branch for the 14-finding report. The
deployment and live retest boundary above still applies.

| Strix area | Branch control now enforced | Regression evidence |
| --- | --- | --- |
| Public pilot/control-plane credential overreach | Pilot keys are inserted with `permissions: []`; SSO and SCIM routes require explicit capabilities; key rotation requires `keys.rotate`/`admin` and preserves the old key's permission scope in the replacement. | Control-plane permission, pilot, and key-rotation tests. |
| SAML tenant confusion / callback state | RelayState is HMAC-bound to the tenant and a nonce, matched to an HttpOnly state cookie, and ACS requires an active directory identity; the cross-site IdP POST uses `SameSite=None; Secure`. | SSO/SAML focused tests and state helpers. |
| Cross-entity gate commit issuance | Cross-entity requests require a verified delegation whose agent is the authenticated caller and whose principal is the requested entity; the delegation id is carried into the issued commit. | Trust-gate security tests plus commit authorization tests. |
| Signoff identity laundering | Both the route and `createAttestation()` require `humanEntityRef` to equal the authenticated accountable actor. | Signoff route/core mismatch regression. |
| WebAuthn enrollment race and lifecycle | Registration completion uses an atomic challenge-lock/credential-insert/consume RPC; credential validity now enforces both `valid_from` and `valid_to`. | WebAuthn registration and signoff-loader tests; migration contract. |
| Same-organization receipt mutation | Same-org membership remains read-only; consume and execution attestation require the creator or an explicit `receipt.consume` / `receipt.execute` capability. | Tenant-binding and v1 receipt route tests. |
| Trust Desk DOCX resource exhaustion | ZIP central-directory preflight caps entries, per-entry expansion, aggregate expansion, and compression ratio before Mammoth. | Oversized DOCX budget regression. |
| Trust Desk bearer replay | The URL bearer is never placed in a cookie; sessions are fresh HMAC envelopes, and bootstrap hashes are atomically single-use in the database. | Trust Desk session tests; bootstrap migration. |
| Gate selector/execution binding | The Gate rechecks material observed fields when recording execution and reliance prefers the execution proof's binding, so changed execution parameters produce `do_not_rely`. | Gate mismatch/reliance regression and 49 node tests. |
| Identity-continuity self-challenge | Authenticated challenger identity is authoritative and ownership-query errors now fail closed instead of allowing the challenge. | EP-IX ownership-failure regression. |
| Dependency and configuration observations | Existing dependency audit remains clean; new database RPCs are service-role-only and the static schema contract tracks them. | `npm audit`, schema-security suite, and migration audit. |

The earlier confirmed non-Gate Sentrix remediations remain in `c0a3db8` on the mainline ancestry: identity-verify authorization, receipt rebind first-write-wins, webhook secret disclosure, rollout mismatch handling, bounded spreadsheet parsing, and IPv4-mapped SSRF handling.

## Hostile audit v3 branch disposition

The following are branch-level dispositions against the audit-v3 items. They are not a claim
that the current Strix run is clean or that the corresponding production paths are deployed.

1. The historical RLS incident remains fixed by migration 113 and is now reasserted by the Fortress migration and source/live contract checks.
2. Direct route write-guard bypasses are closed for the audited routes.
3. Direct `auth.entity` use is closed at the route boundary. Routes use `authEntityId`, `authEntityDbId`, `authEntityActor`, or another named allowlisted projection, and CI rejects raw access.
4. SSO service-role-derived and predictable fallback secrets are removed.
5. The audited direct environment reads in logger, SIEM, SSO, and WebAuthn code are centralized through `lib/env.js`; logger now consumes `getLoggerConfig()` and has no direct `process.env` reads.
6. WebAuthn uses the shared canonicalizer, and cross-implementation vectors are tested. The published portable verifier retains its compatible implementation for package independence; valid EP I-JSON vectors are asserted byte-for-byte.
7. The Supabase service client is now created per call with session persistence and auto-refresh disabled; the process-scoped singleton is removed.
8. Sensitive rate-limit categories require durable Redis in production (or fail closed); sensitive routes no longer use an undefined category that falls back to the generic read limiter.
9. The public key-revocation route no longer exposes the operational rotation procedure in source comments.
10. Gate function wrappers await all async input providers; a missing receipt cannot be reclassified as an unguarded action through a Promise-valued selector.
11. Approver enrollment is capability-gated at both WebAuthn registration phases; organization binding alone is not treated as enrollment authorization.

## Release blockers and external validation

These remain open until verified against the target deployment and the active Strix report:

- Apply `supabase/migrations/20260718145410_fortress_db_security_invariants.sql` to the target Supabase project, then run the live schema contract. No production database credentials were available during this pass.
- Apply the new forward migrations `20260718160000_api_key_rotation_scope.sql`, `20260718161000_webauthn_registration_atomic.sql`, and `20260718162000_trust_desk_bootstrap_once.sql` before exercising the hardened production routes.
- Configure and verify production `SSO_STATE_SECRET`, `SSO_SESSION_SECRET`, and Upstash credentials before enabling the corresponding production paths.
- Deploy a Vercel preview and run the release/build/security gates against that deployment. Production deployment should follow only after the preview and live migration checks pass.
- External provider custody, licensing, and transaction settlement remain outside EMILIA’s control plane; the website and Action Escrow contract deliberately do not claim otherwise.
