# Strix / Hostile Audit Remediation — 2026-07-18

## Scope and evidence boundary

The Strix completion email reported 10 findings: 7 high, 1 medium, and 2 low. The email summary was available during this remediation; the linked full report was not accessible from this environment. This document therefore records verified code and test evidence, not a claim that every detail of the linked report was independently re-performed.

The hostile-code audit v3 was available as a source report and was checked against the integration tree.

## Remediations shipped on the integration branch

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
| Service-client isolation | `getServiceClient()` creates a non-persistent client per call with session persistence disabled; no process-scoped singleton remains. | `tests/service-client-isolation.test.js`; 91 focused security tests passed. |
| Durable rate-limit posture | Sensitive routes use named durable-required categories; unknown `write` categories were removed, and `protocol_read` is explicit instead of silently falling back to generic reads. | `lib/rate-limit.js`; production without Upstash fails closed for sensitive categories. |
| Public Action Escrow surface | Website content now explains the action-bound approval flow, exact outcomes, refusal codes, and simulated-provider/custody boundary. | `4d22394`; focused copy tests and Next build passed in the worker lane. |

The earlier confirmed non-Gate Sentrix remediations remain in `c0a3db8` on the mainline ancestry: identity-verify authorization, receipt rebind first-write-wins, webhook secret disclosure, rollout mismatch handling, bounded spreadsheet parsing, and IPv4-mapped SSRF handling.

## Hostile audit v3 disposition

1. The historical RLS incident remains fixed by migration 113 and is now reasserted by the Fortress migration and source/live contract checks.
2. Direct route write-guard bypasses are closed for the audited routes.
3. Direct `auth.entity` use is closed at the route boundary. Routes use `authEntityId`, `authEntityDbId`, `authEntityActor`, or another named allowlisted projection, and CI rejects raw access.
4. SSO service-role-derived and predictable fallback secrets are removed.
5. The audited direct environment reads in logger, SIEM, SSO, and WebAuthn code are centralized through `lib/env.js`; logger now consumes `getLoggerConfig()` and has no direct `process.env` reads.
6. WebAuthn uses the shared canonicalizer, and cross-implementation vectors are tested. The published portable verifier retains its compatible implementation for package independence; valid EP I-JSON vectors are asserted byte-for-byte.
7. The Supabase service client is now created per call with session persistence and auto-refresh disabled; the process-scoped singleton is removed.
8. Sensitive rate-limit categories require durable Redis in production (or fail closed); sensitive routes no longer use an undefined category that falls back to the generic read limiter.
9. The public key-revocation route no longer exposes the operational rotation procedure in source comments.

## Release blockers and external validation

- Apply `supabase/migrations/20260718145410_fortress_db_security_invariants.sql` to the target Supabase project, then run the live schema contract. No production database credentials were available during this pass.
- Configure and verify production `SSO_STATE_SECRET`, `SSO_SESSION_SECRET`, and Upstash credentials before enabling the corresponding production paths.
- Deploy a Vercel preview and run the release/build/security gates against that deployment. Production deployment should follow only after the preview and live migration checks pass.
- External provider custody, licensing, and transaction settlement remain outside EMILIA’s control plane; the website and Action Escrow contract deliberately do not claim otherwise.
