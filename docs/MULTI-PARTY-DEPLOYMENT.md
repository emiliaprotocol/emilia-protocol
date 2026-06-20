<!-- SPDX-License-Identifier: Apache-2.0 -->
# Multi-party signoff — deployment layer

This documents how the multi-party quorum (the "two-person rule" / trail of
signatories) is fielded on top of the existing single-signoff system, and the
remaining wiring to finish it. The **enforcement core is already built and
tested** (`lib/signoff/quorum-session.js`, cross-language `verifyQuorum`); this
is the integration plan for the deployed app.

## Model (no new tables)
A quorum is **one challenge with many attestations** — the schema already
supports it:

| Table | Role for a quorum |
|---|---|
| `signoff_challenges` | one row per gated action; **new** nullable `quorum_policy` JSONB (migration 094). NULL = single-signoff, unchanged. |
| `signoff_attestations` | one row per approver (already `challenge_id`-keyed, many-per-challenge). |
| `approver_credentials` | each approver's enrolled `public_key_spki`. |
| `webauthn_challenges` | the canonical authorization `context` each approver signed. |
| `signoff_consumptions` | one-time consume of the (now quorum-gated) signoff. |

`quorum_policy` shape: `{ mode: "ordered"|"threshold", required, approvers:[{role,approver}], distinct_humans, window_sec }`.

## The two enforcement hooks (compose `lib/signoff/quorum-session.js`)

### 1. At attest — `canAccept()` before writing the attestation
In `lib/signoff/attest.js`, when the challenge has a `quorum_policy`:
1. Load the challenge's already-accepted attestations → map each to a quorum
   **member** `{ role, approver_public_key, signoff:{ context, webauthn } }`
   (context from `webauthn_challenges`, key from `approver_credentials.public_key_spki`).
2. Build the incoming candidate member the same way.
3. `canAccept(quorum_policy, action_hash, existingMembers, incoming, { rpId })`.
   - If `!ok`, reject the attestation with the returned `reason`
     (`duplicate_human` · `out_of_order` · `ineligible_role` · `action_mismatch`
     · `window_exceeded` · `non_increasing_time` · `invalid_signature`) — the
     bad signer never enters the trail.
   - If `ok`, proceed with the existing atomic attestation write.

### 2. At consume — `quorumGate()` must be satisfied
In `lib/signoff/consume.js`, when the challenge has a `quorum_policy`:
1. Load **all** accepted attestations for the challenge → members (as above).
2. `const gate = quorumGate(quorum_policy, action_hash, members, { rpId })`.
3. If `!gate.satisfied`, throw `SignoffError('QUORUM_NOT_SATISFIED', 409)` — the
   downstream action cannot consume an unsatisfied quorum. Single-signoff
   challenges (`quorum_policy IS NULL`) skip this gate entirely (unchanged).

> The consume gate is the security-critical line: an action is authorized only
> when the full quorum holds. It reuses the same fail-closed predicate proven in
> cross-language conformance (`conformance/run.mjs`), so server enforcement and
> offline verification agree by construction.

## API surface
- **Initiate**: the signoff-request path accepts an optional `quorum_policy`
  (persisted on the challenge). No new route — an additive field on the existing
  request.
- **Attest**: the existing per-approver attest route, now gated by `canAccept`.
  Each approver in the roster attests once; UI shows the trail state.
- **Status**: a read of the challenge + its attestations → `quorumGate` result
  (`satisfied`, per-check, which roles remain).
- **Consume**: existing route, now gated by `quorumGate`.

## Member mapping (the one helper to add)
`attestationsToMembers(challenge, attestations, credentials, webauthnChallenges)`
→ `[{ role, approver_public_key, signoff: { '@type':'ep.signoff', context, webauthn } }]`.
Pure; unit-testable against fixtures. This is the only new lib code beyond the
already-built core.

## Prod rollout runbook
1. **Apply migration 094** to prod Supabase (additive column; zero downtime):
   `supabase db push` (or Studio SQL) — verify `quorum_policy` exists on
   `signoff_challenges`.
2. Ship the `attest`/`consume` hooks behind the `quorum_policy IS NULL` guard
   (single-signoff paths are untouched; quorum paths activate only when a policy
   is set).
3. E2E: issue a quorum challenge (ordered PO→AO→IG), attest each on real/sim
   devices, confirm a duplicate/out-of-order signer is rejected at attest, and
   that consume is blocked until the trail is satisfied. Mirror the `/try/multi-party`
   demo flow against the live API.

## Status (honest)
- **Built + tested**: the enforcement core (`quorum-session.js`, `verifyQuorum`
  in JS/Python/Go), the `/try/multi-party` demo, and migration 094 (additive).
- **Remaining to field**: the `attestationsToMembers` helper + the two hooks in
  `attest.js`/`consume.js`, applying migration 094 to prod, and live E2E. This
  is a deliberate, reviewed step because `consume.js` gates real actions —
  not a capability to claim as shipped until it is wired and verified end-to-end.
