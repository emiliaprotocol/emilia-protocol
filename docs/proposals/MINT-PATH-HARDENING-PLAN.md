# Mint-Path Hardening: Verification Plan

Run this before merging `mint-path-hardening.patch` to main. main deploys to production within minutes, and this patch touches the production authorization decision on the receipt-mint path, so verify in staging first.

## What changed and why

Two files change. No migrations, no schema, no new env vars, no dependency changes.

### 1. `lib/guard-policies.js` (the pure policy evaluator, consumed by BOTH the mint route and the precheck adapters)

- Added `MINT_CRITICAL_FLOOR_ACTIONS`: a deliberately narrow set of unconditionally-critical action types: `benefit_bank_account_change`, `beneficiary_creation`, `large_payment_release`.
- Added `applyCriticalKeyClassFloor(decision, input)`: if a base decision is a bare `allow` AND the action type is in that set, it escalates the decision to `allow_with_signoff` with `requiredAssurance: 'A'` and prepends a reason string. It never relaxes a `deny` or an existing signoff, and it is inert for every other action type.
- Wired the floor into `evaluateGuardPolicy()`: `applyCriticalKeyClassFloor(stampAssurance(basePolicy(input), input), input)`, applied before AML screening so AML can only escalate further (an AML `deny` still trumps below; an AML `signoff` becomes redundant-but-harmless).

Why: `basePolicy()` had no escalation branch for `benefit_bank_account_change` or `beneficiary_creation`, and `large_payment_release` only escalated at amount >= $50k. So a caller could mint any of these as a bare software-tier `allow` receipt (no human signoff) by omitting a money-destination changed field, or by supplying a sub-$50k amount, or by omitting amount. That is the same class of fail-open that `packages/require-receipt` and `packages/gate` already close at author/issue time with their `critical -> class_a` floor. This brings the mint path to parity. The set is intentionally narrower than the full `CLASS_A_ACTIONS` list: `benefit_address_change` is excluded because its criticality is field-conditional by design (a cosmetic `display_name` change is meant to default-allow; only identity/routing fields escalate, which `basePolicy` already handles).

### 2. `app/api/v1/trust-receipts/route.js` (the mint route, rules-engine v0 shadow input)

- Changed the shadow rules-engine `actor` input from the hardcoded fail-OPEN `assurance_level: 'high'` / `mfa_verified: true` to the fail-SAFE weakest credible values `assurance_level: 'low'` / `mfa_verified: false`.
- Replaced the misleading comment `Auth is bearer-token + middleware-enforced; treat as MFA-strong` with an honest explanation plus the wiring note.

Why: a bearer API key (`ep_live_...`) is a long-lived shared secret. It does not establish MFA, and it carries no WebAuthn user-verification (UV) signal. `authenticateRequest` resolves the key via the `resolve_authenticated_actor` RPC and returns `{ entity, permissions }` with no assurance or UV field (confirmed in `lib/supabase.js` and `supabase/migrations/125_resolve_authenticated_actor_strip_secrets.sql`). Hardcoding `mfa_verified: true` meant that if the shadow engine is ever promoted to enforce, every bearer request would clear the rules-engine section 4.5 MFA/assurance hard-deny gate. The honest shadow result for a bearer-only request is now `DENY` with reason `MFA_REQUIRED`.

### Defect 3 (bearer-as-MFA-strong / legacy Class-C signing): no additional code change required

The misleading route comment and the fabricated shadow input were the only mint-time expressions of "treat bearer as MFA-strong"; both are fixed above. The downstream enforcement chain already fails closed correctly and was left untouched:
- `lib/guard-signoff.js` rejects a bearer-key approval (`key_class: 'C'`) with `insufficient_assurance` when the receipt's `required_assurance === 'A'`.
- `app/api/v1/trust-receipts/[receiptId]/consume/route.js` refuses consume (`insufficient_assurance`) when `required_assurance === 'A'` and the recorded signoff `key_class !== 'A'`.

The two changes compose: the mint floor now stamps `required_assurance: 'A'` onto the previously-fall-through critical actions, and these existing consume/approve gates then refuse a bare Class-C (bearer) approval. `key_class: 'C'` remains the honest weakest default and stays correctly guarded; it is not a bypass.

## Behavior change on the live mint path

Requests that PREVIOUSLY returned `decision: allow` / `signoff_required: false` / `receipt_status: issued` and NOW return `decision: allow_with_signoff` / `signoff_required: true` / `required_assurance: A` / `receipt_status: pending_signoff`:

1. `action_type: large_payment_release` with `amount` below $50,000 (for example $2,000). Note: the mint route requires a finite `amount` for `large_payment_release` (via `AMOUNT_REQUIRED_ACTIONS` in `lib/guard-action-inputs.js`), so the amount-omitted case is already a 400 on the route; the omitted-amount escalation only manifests through direct `evaluateGuardPolicy` callers.
2. `action_type: beneficiary_creation` when no money-destination field is named in `target_changed_fields`.
3. `action_type: benefit_bank_account_change` when no money-destination field is named in `target_changed_fields`.

These now require a Class-A (named-human WebAuthn/passkey) or quorum signoff before the action can be consumed. This is the intended hardening: a critical, typically irreversible money action can no longer be minted at a bare software tier.

The rules-engine v0 SHADOW audit event (`event_type: rules-engine.v0.shadow`, only written when `EP_RULES_ENGINE_V0=enabled`) now records `DENY / MFA_REQUIRED` for bearer-only requests instead of a fabricated `REQUIRE_*` result. This is observability only. It does NOT change the response shape, the live `decision`, or block anything, because the shadow path is wrapped in try/catch and is pure telemetry. If ops dashboards read the shadow field, they will see the honest bearer posture.

## Blast radius (which requests newly escalate)

- Scope of the floor: it lives in `evaluateGuardPolicy`, so it applies to BOTH the generic mint route (`POST /api/v1/trust-receipts`) AND the precheck adapters that funnel through `lib/guard-adapter.js` (`/api/v1/adapters/{gov,fin}/*/precheck`). This is intentional: the same critical action must not be mintable at a weak tier via either path.
- Only three action types are affected, and only when they would otherwise have been a bare `allow`. Every action type that already escalated in `basePolicy` (the `gov.*` family, `caseworker_override`, `ai_agent_payment_action`, any money-destination field change) is unchanged. Non-critical action types are unchanged.
- DENY decisions are unchanged. Existing signoff decisions are unchanged (the floor is a no-op unless the decision was a bare `allow`).
- The shadow-input change affects ONLY the shadow audit event, and ONLY when `EP_RULES_ENGINE_V0=enabled`. With the flag off (default) there is zero behavioral change from that edit.

## What to check in staging (s1r2 or local)

Auth with a real bearer key (`Authorization: Bearer ep_live_...`).

1. Sub-threshold payment release now escalates:
   - `POST /api/v1/trust-receipts` with `{ action_type: "large_payment_release", target_resource_id: "...", amount: 2000, currency: "USD" }`.
   - EXPECT `201` with `decision: "allow_with_signoff"`, `signoff_required: true`, `required_assurance: "A"`, `receipt_status: "pending_signoff"`.
2. Beneficiary creation without a money-destination field now escalates:
   - `POST /api/v1/trust-receipts` with `{ action_type: "beneficiary_creation", target_resource_id: "..." }` (no `target_changed_fields`).
   - EXPECT `decision: "allow_with_signoff"`, `required_assurance: "A"`.
3. Above-threshold and money-destination paths are unchanged:
   - `large_payment_release` with `amount: 82000` still returns `allow_with_signoff` (unchanged), and `benefit_bank_account_change` with `target_changed_fields: ["bank_account"]` still returns `pending_signoff` (unchanged).
4. Consume enforces the floor end-to-end:
   - Take a newly-floored receipt (case 1 or 2), attempt to consume it with only a bearer-key (Class-C) signoff recorded.
   - EXPECT `insufficient_assurance` (the consume gate refuses a non-Class-A signoff for a `required_assurance: A` receipt).
5. Shadow honesty (optional, flag-gated): set `EP_RULES_ENGINE_V0=enabled`, mint any receipt, read the second `audit_events` row (`event_type: rules-engine.v0.shadow`).
   - EXPECT `rules_engine_decision: "DENY"` and `rules_engine_reason_codes` containing `MFA_REQUIRED` for a bearer-only request. Confirm the live `guard_policy_decision` in the same row is unaffected by the shadow.
6. Non-critical actions unchanged: a benign action (for example `benefit_address_change` with `target_changed_fields: ["display_name"]`) still returns `decision: "allow"`, `signoff_required: false`.

## Tests

Run at repo root (vitest) and per-package (node --test).

- `npx vitest run tests/guard-policies.test.ts tests/rules-engine-shadow.test.ts tests/rules-engine.test.ts tests/v1-api.test.ts tests/quorum-org-template.test.ts tests/guard-tier.test.ts tests/guarded-assurance.test.ts tests/assurance-proof-binding.test.ts tests/guard-adapter-aml.test.ts tests/execution-binding-contract.test.ts tests/validation.test.ts tests/guard-authority.test.ts tests/aml-screening.test.ts tests/signoff-challenge.test.ts tests/route-coverage.test.ts`
  - Result on this patch: 601 passed, 8 failed (see below).
- `cd packages/require-receipt && node --test` -> 41 passed, 0 failed.
- `cd packages/gate && node --test` -> 287 passed, 0 failed.

### The 8 failing tests each assert the OLD fail-open behavior. A human must decide whether to update them; do NOT weaken the fix to satisfy them.

All 8 assert that a critical action (a payment release, or a bearer-only request in the shadow engine) resolves to a bare `allow` or a fabricated MFA-verified result. Each one is asserting exactly the defect this patch closes.

1. `tests/guard-policies.test.ts` > `evaluateGuardPolicy: large-payment threshold` > `does NOT require signoff on payment < $50,000` (amount 49,999). A sub-$50k payment release is still money movement; it should not mint at a bare tier. Update to expect `allow_with_signoff` + `requiredAssurance: 'A'`.
2. `tests/guard-policies.test.ts` > `evaluateGuardPolicy: large-payment threshold` > `skips threshold when amount is undefined`. A payment release with no amount must not default to allow (fail-closed). Update to expect `allow_with_signoff`.
3. `tests/aml-screening.test.ts` > `guard-policy AML integration` > `a clean action with AML context still allows, with no signals` (`large_payment_release`, amount 2000). Update to expect `allow_with_signoff` (the AML "no signal" assertion can be re-expressed by checking `aml_signals` is empty rather than the decision being `allow`).
4. `tests/aml-screening.test.ts` > `guard-policy AML integration` > `omitting AML context preserves the exact prior decision shape` (`large_payment_release`, amount 2000). Update the expected baseline decision to `allow_with_signoff`.
5. `tests/guard-adapter-aml.test.ts` > `guard adapter + AML` > `allows a clean financial action (no AML signals)` (`large_payment_release`, amount 2000). Update to expect `allow_with_signoff`.
6. `tests/guard-adapter-aml.test.ts` > `guard adapter + AML history (self-lookup)` > `a first-ever transfer to a counterparty (clean amount) allows and records history` (`large_payment_release`, amount 2000). The history-recording assertion is still valid; update the decision expectation to `allow_with_signoff`.
7. `tests/guard-adapter-aml.test.ts` > `guard adapter + PIP-007 initiator attestation` > `omits the attestation (null) on a clean ALLOW` (`large_payment_release`, amount 2000). This case is no longer a clean ALLOW; either move the "null attestation" assertion to a genuinely non-critical action type, or update it to expect the floor's initiator attestation.
8. `tests/rules-engine-shadow.test.ts` > `rules-engine v0 shadow signal — wiring` > `shadow event correctly identifies vendor_bank_account_change as REQUIRE_SECOND_APPROVAL or stronger`. With the fail-safe `mfa_verified: false`, the shadow engine now hard-denies with `MFA_REQUIRED` (required_approvals 0) before reaching the quorum layer. This test's expectation was built on the fabricated `mfa_verified: true`. Update it to expect `DENY` / `MFA_REQUIRED`, and add a separate test that supplies a genuine UV/MFA signal once that wiring exists.

Recommendation: update these 8 tests to assert the hardened behavior in the same PR that lands this patch, so the suite stays green and the new invariant is locked in. Keep at least one test per file that pins the exact new expectation (`allow_with_signoff` + `requiredAssurance: 'A'` for the payment-release floor; `DENY` + `MFA_REQUIRED` for the bearer-only shadow).

## Follow-up wiring (surfacing a real WebAuthn UV flag)

To ever raise the shadow input above the fail-safe floor (and, more importantly, to let a mint request carry a proven strong-auth signal), a genuine WebAuthn user-verification signal must be threaded through `authenticateRequest`:

- Today WebAuthn UV lives at signoff/consume time (a Class-A device-key / passkey assertion with a UV flag), NOT at mint time. The bearer path has no UV.
- To assert `assurance_level: 'high'` / `mfa_verified: true` at mint, `authenticateRequest` (or a dedicated mint-time verifier) would need to accept and cryptographically verify a fresh UV-bearing assertion presented on the mint call, then surface a verified `{ assurance_level, mfa_verified, uv }` on the auth context.
- Until that exists, keep the weakest values. Never trust a body-supplied assurance/mfa value: the caller (or agent) controls the body, so a body-declared strength is not a security signal.

## Rollback

Single revert of `mint-path-hardening.patch` restores prior behavior. No data migration, no schema change, no state to unwind: the patch only changes an in-memory policy decision and a telemetry input.

- Fast partial rollback of the shadow-input change alone: set `EP_RULES_ENGINE_V0` unset (default). With the flag off, the shadow block does not run, so the shadow-input edit has no runtime effect. The key-class floor still applies (it is not flag-gated).
- To disable the key-class floor without a full revert, revert only the two `lib/guard-policies.js` hunks (the `MINT_CRITICAL_FLOOR_ACTIONS` const + `applyCriticalKeyClassFloor` function and its one call site in `evaluateGuardPolicy`). The route-file change is independent and can stay.
- Because receipts already minted under the floor are self-describing (they carry `required_assurance: 'A'` and `receipt_status: pending_signoff`), a rollback does not corrupt or orphan them; they simply continue to require a Class-A signoff to consume, which is stricter, not looser.
