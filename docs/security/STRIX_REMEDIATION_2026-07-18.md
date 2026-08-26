# Strix remediation register - 2026-07-18 report

> **Status: source-remediated and deployed; external retest pending. This is not a closure memo.**
> This register covers the 18 reported findings: 1 critical, 9 high, 5 medium,
> and 3 low. The controls and regressions below are present in the current
> production tree. The production deployment, configuration presence, migration
> state, and live Trust Desk bootstrap behavior were verified on 2026-08-26.
> Those checks do not establish independent closure. A finding may be marked
> closed only after Strix retests the exact deployed revision and confirms the
> result.

## Evidence boundary

In this document, **source-remediated** means the reported source path has a
specific fail-closed control and regression artifact in the production tree.
**Deployed** means the exact source revision is served by the production alias,
the governed migration ledger matches the live schema through
`20260826130000`, and required production configuration names are present as
encrypted values. It does not disclose or attest the secret values themselves.
**External retest pending** means the finding remains open from an independent
assurance perspective. Branch tests are not a substitute for a retest against
the target deployment.

The table is limited to STRIX-1, STRIX-2, STRIX-4, STRIX-6, and STRIX-11 through
STRIX-24. It does not silently merge these findings with an older Strix summary
or with the separate hostile-code audit.

## Finding-by-finding disposition

| ID | Severity | Source disposition | Control now enforced | Regression evidence |
| --- | --- | --- | --- | --- |
| STRIX-1 | High | Source-remediated; external retest pending | `gate.guard()` awaits selector, receipt, observed-action, admissibility, and reliance providers. If an async selector resolves to a protected action without a receipt, the Gate returns `receipt_required` and never invokes the effect. | `packages/gate/gate.test.ts`, especially the async-provider and missing-receipt regressions. |
| STRIX-2 | High | Source-remediated; external retest pending | WebAuthn registration completion uses `complete_webauthn_registration_atomic`, which locks and validates the one-time challenge, inserts the credential, and consumes the challenge in one database operation. A consumed challenge is rejected as replay. | `app/api/v1/approvers/webauthn/register-verify/route.ts`; `supabase/migrations/20260718205655_webauthn_registration_atomic.sql`; `tests/webauthn-registration-route.test.ts`; `tests/agent-adoption-postgres.integration.test.ts`. |
| STRIX-4 | High | Source-remediated; external retest pending | Both WebAuthn enrollment phases require the explicit `approver.enroll` capability or the documented `admin` super-capability, and the approver remains bound to the authenticated organization. Organization membership alone is not enrollment authority. | `lib/approver-enrollment-auth.ts`; `tests/webauthn-registration-route.test.ts`. |
| STRIX-6 | Low | Source-remediated; external retest pending | The `/spec` markdown boundary escapes raw HTML and attribute-breaking content, rejects executable URL schemes, escapes code bytes, and allowlists fenced-code language tokens before rendering. | `lib/spec-markdown.ts`; `tests/spec-markdown-security.test.ts`; `tests/site-spec-route.test.ts`. |
| STRIX-11 | Critical | Source-remediated; external retest pending | Independent selector identities are resolved conjunctively in both the legacy EP-ACTION-RISK resolver and the Action Control v0.2 resolver. Contradictory `id`, action alias, protocol, and complete transport fields cannot fall through a first-match path; the Gate synthesizes a protected conflict result and refuses with `manifest_selector_conflict`. | `packages/require-receipt/src/index.ts`; `packages/require-receipt/selector-confusion.test.ts`; `packages/gate/src/action-control-manifest.ts`; `packages/gate/gate.test.ts`; `tests/action-control-manifest.test.ts`; `tests/mutation-security-kernel.test.ts`. |
| STRIX-12 | High | Source-remediated; external retest pending | SSO configuration writes require `sso.manage` or `admin`; reads require `sso.read`, `sso.manage`, or `admin`. Ordinary tenant keys and observe-scope pilot keys cannot administer SSO. | `app/api/sso/connections/route.ts`; `tests/control-plane-permissions.test.ts`; `tests/pilot-sandbox-controlplane-scope.test.ts`. |
| STRIX-13 | High | Source-remediated; external retest pending | Receipt creation ownership is authoritative. A same-organization peer no longer gains access from membership alone and needs the exact `receipt.read`, `receipt.evidence`, `receipt.consume`, or `receipt.execute` capability for the requested operation; same-org `admin` remains the explicit super-capability, while cross-org access is denied. | `lib/tenant-binding.ts`; `tests/strix-13-receipt-authorization.test.ts`; `tests/tenant-binding.test.ts`; route regressions in `tests/v1-api.test.ts` for read, evidence, consume, and execution. |
| STRIX-14 | Medium | Source-remediated; external retest pending | `check()` and `guard()` do not accept selector metadata as execution input. In particular, selector-sourced `observedAction` and `actionDetails` cannot authorize raw function arguments for a different action. Explicit deployer-owned action mappings remain trusted integration code and therefore remain a documented trust boundary; sealed adapters and registered operations provide the strongest binding. | `packages/gate/src/index.ts`; the `STRIX-14` regression in `packages/gate/gate.test.ts`; execution-binding regressions in the same suite. |
| STRIX-15 | High | Source-remediated; external retest pending | The attest route and `createAttestation()` both require `humanEntityRef` to equal the authenticated accountable actor. A caller cannot place another identity into the signed approval trail. | `app/api/signoff/[challengeId]/attest/route.ts`; `lib/signoff/attest.ts`; `tests/signoff-attest.test.ts`. |
| STRIX-16 | High | Source-remediated; external retest pending | One Trust Desk request has a shared budget across classification and answering. Public intake and triage are each capped at 6 provider calls, 12,000 estimated input/output token units, and 20 seconds of aggregate LLM wall-clock time; the separately authenticated internal workflow retains the documented 48-call, 100,000-unit, 50-second ceiling. Every path also enforces at most 200 questions, 8,000 characters per question, and 200,000 aggregate question characters. Provider reservation occurs before network invocation, and one abort deadline spans connection establishment, response headers, error-body reads, and JSON-body parsing. The durable, fail-closed public throttle admits at most 10 scans per source IP per hour. An exhausted, expired, missing, or unavailable budget/throttle refuses rather than invoking another model call. | `lib/trust-desk/resource-budget.ts`; `lib/trust-desk/pipeline.ts`; `lib/trust-desk/llm.ts`; `lib/rate-limit.ts`; `app/api/trust-desk/intake/route.ts`; `app/api/trust-desk/triage/route.ts`; `tests/trust-desk-resource-budget.test.ts`; `tests/trust-desk-intake-resource-profile.test.ts`; `tests/trust-desk-triage-route.test.ts`; `tests/rate-limit.test.ts`. |
| STRIX-17 | High | Source-remediated and deployed; external retest pending; required production configuration present | SAML RelayState is HMAC-bound to the tenant and a nonce, matched to a short-lived `HttpOnly; Secure; SameSite=None` browser cookie, and verified before tenant configuration is selected. The assertion is verified under that tenant's IdP key, replay-consumed, and accepted only for an active directory identity. Production has separate encrypted `SSO_STATE_SECRET` and `SSO_SESSION_SECRET` configuration and still fails closed if either value is absent or invalid. | `app/api/sso/saml/login/route.ts`; `app/api/sso/saml/acs/route.ts`; `lib/sso/state.ts`; `lib/sso/session.ts`; `supabase/migrations/20260628151330_103_saml_consumed_assertions.sql`; `tests/sso-state.test.ts`; `tests/sso-saml.test.ts`. |
| STRIX-18 | Medium | Source-remediated and deployed; external retest pending; production bootstrap rotated and configuration present | A query-string bootstrap value never authenticates and is scrubbed by a `303` redirect to the clean URL without setting a cookie or consuming the token. The clean page uses a no-store form; only a bounded, same-origin `POST` may exchange the bootstrap secret. Reviewer sessions are signed with a separate `TRUST_DESK_SESSION_SECRET`, never with the historically exposed bootstrap token. Production now has a rotated encrypted `TRUST_DESK_INTERNAL_TOKEN`, an independent encrypted `TRUST_DESK_SESSION_SECRET`, and `TRUST_DESK_REVIEWER_ID`. | `app/internal/trust-desk/auth/route.ts`; `lib/trust-desk/auth.ts`; `lib/env.ts`; `tests/trust-desk-bootstrap-route.test.ts`; `tests/trust-desk-auth.test.ts`; `tests/trust-desk-review-route.test.ts`. |
| STRIX-19 | Medium | Source-remediated; external retest pending | Public pilot sandbox API keys are created with the single `observe` permission and a durable server-written observe marker. A centralized authorization floor admits those credentials only to the exact reviewed GovGuard and FinGuard precheck routes plus their actor-scoped sandbox report. The floor evaluates pilot scope before the normal read-method path, so current and legacy pilot identities are denied on every other authenticated read or mutation even if a stale key also carries `read`, `write`, or `admin`. Anonymous provisioning is independently limited to five identities per hour per source IP by the fail-closed durable `pilot_sandbox_provision` middleware category. | `app/api/pilot/sandbox/provision/route.ts`; `lib/auth/observe-scope.ts`; `lib/auth/protocol-request-authorization.ts`; `middleware.ts`; `lib/rate-limit.ts`; `supabase/migrations/20260826010000_pilot_observe_permission.sql`; `tests/protocol-request-authorization.test.ts`; `tests/pilot-sandbox-controlplane-scope.test.ts`; `tests/private-equity-page.test.ts`. |
| STRIX-20 | Medium | Source-remediated; external retest pending | `POST /api/identity/continuity/challenge` derives `challenger_id` exclusively from the authenticated entity. A body-supplied challenger cannot override it or manufacture a self-challenge bypass. | `app/api/identity/continuity/challenge/route.ts`; exact route-level regression in `tests/identity-continuity-challenge-route-security.test.ts`. |
| STRIX-21 | Medium | Source-remediated; external retest pending | Cross-entity Gate commit issuance requires a verified delegation whose agent is the authenticated caller and whose principal is the requested entity. Agent mismatch and principal mismatch both refuse before an allow commit can be issued. | `app/api/trust/gate/route.ts`; exact route-level mismatch regressions in `tests/trust-gate-security.test.ts`. |
| STRIX-22 | Low | Source-remediated; external retest pending | WebAuthn signoff credential loading includes `valid_from` and `valid_to` and rejects credentials that are not yet valid or are expired before signature verification or state mutation. | `lib/webauthn-signoff.ts`; `app/api/v1/signoffs/[signoffId]/approve-webauthn/route.ts`; `tests/webauthn-approve-route.test.ts`. |
| STRIX-23 | High | Source-remediated; external retest pending | SCIM provisioning-token mint and list operations require `scim.manage` or `admin`; generic read/write principals and observe-scope pilot keys are refused. | `app/api/scim/v2/provisioning-token/route.ts`; `tests/control-plane-permissions.test.ts`; `tests/pilot-sandbox-controlplane-scope.test.ts`. |
| STRIX-24 | Low | Source-remediated; external retest pending | DOCX intake parses a strict single-disk ZIP layout, rejects encryption, data descriptors, ZIP64, unsupported flags/methods, aliased or overlapping local entries, central/local-header disagreement, and trailing compressed payload bytes, then independently inflates every deflated entry under hard output limits before Mammoth sees the document. The parser verifies actual compressed bytes consumed and actual expanded sizes, with 16 MiB per-entry and 64 MiB aggregate ceilings; it does not trust attacker-declared central-directory sizes. | `lib/trust-desk/extractor.ts`; exact mismatch, overlap, trailing-byte, per-entry, ratio, and aggregate-limit regressions in `tests/trust-desk-extractor-budget.test.ts`. |

## Deployment and independent-validation requirements

The source and deployment requirements were completed against production on
2026-08-26:

1. The governed ledger and live schema contract agree through remote migration
   `20260826130000`, with 204 remote versions, 1 private historical version,
   and 0 pending migrations.
2. Separate encrypted production entries are present for `SSO_STATE_SECRET`
   and `SSO_SESSION_SECRET`. No value was printed or copied during verification.
3. `TRUST_DESK_INTERNAL_TOKEN` was rotated. Separate encrypted production
   entries are present for `TRUST_DESK_SESSION_SECRET` and
   `TRUST_DESK_REVIEWER_ID`.
4. The production `/proof` source revision matched the merged `main` head at
   verification. A query-token probe returned a clean `303`, an invalid
   same-origin form exchange returned `401`, and a cross-origin form exchange
   returned `403`.
   The deployed intake paths use the governed 6-call, 12,000-unit, 20-second
   public resource profile. The request-scoped resource budget remains a
   deterministic request control, not a distributed portfolio-wide cost ledger.

Independent closure still requires Strix to retest every finding against this
exact deployed revision. Source-remediated, deployed, and externally retested
remain separate states; none of the rows above claims the final state yet.

## Residual trust boundary for action binding

The STRIX-14 change removes selector metadata as an execution-data source. It
does not make an arbitrary deployer callback self-describing. If an integration
provides an explicit `observedAction` mapper, that mapper is trusted integration
code and must derive the canonical action from the same function inputs that
reach the effect. Where feasible, use the sealed adapter or registered-operation
path so authorization and execution share one mapping boundary.
