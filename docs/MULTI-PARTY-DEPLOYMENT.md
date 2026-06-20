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

## ⚠️ Corrected target: the LIVE Class-A path is the `audit_events` subsystem
Tracing the deployed code (2026-06-20) surfaced that there are **two signoff
subsystems**, and the one that matters for multi-party device approval is **not**
the one this doc first assumed:

| Subsystem | Storage | Verifier | Status |
|---|---|---|---|
| **Class-A WebAuthn** (the live, multi-party-relevant path; what `/try/multi-party` mirrors) | decisions in `audit_events.after_state` (`guard.signoff.approved`, with `context` + `webauthn` + `approved_action_hash`); approver keys in `approver_credentials` | `@simplewebauthn/server` at decision time | **this is where the quorum gate belongs** |
| **Bearer attestation** (older) | `signoff_attestations` / `signoff_consumptions` (`lib/signoff/consume.js`) | n/a | migration 094 + the `consume.js` hook above target THIS — the wrong subsystem for Class-A |

**So the correct fielding for the real path is:**
1. **Persist the quorum policy at issuance** in the Class-A subsystem (on the
   signoff request / receipt), *not* on `signoff_challenges`. (Migration 094's
   column is harmless but aimed at the bearer subsystem.)
2. **`canAccept()` hook** goes in `app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js`
   — before inserting the `guard.signoff.approved` decision, map the already-
   recorded decisions for this receipt via `attestationsToMembers()` and reject
   a bad/duplicate/out-of-order signer.
3. **`quorumGate()` hook** goes in the Class-A authorization-before-action path —
   **`app/api/v1/trust-receipts/[receiptId]/consume/route.js`** (which reads the
   `guard.signoff` decisions from `audit_events`), not `lib/signoff/consume.js`.
   Load all `guard.signoff.approved` decisions for the receipt →
   `attestationsToMembers()` → `quorumGate()`; block consume unless satisfied.

The **`attestationsToMembers()` bridge is built and tested**
(`lib/signoff/attestation-members.js`) against this exact stored shape, and the
round-trip test proves the mapped members pass the real `quorumGate`.

## Status (honest) — SHIPPED on the Class-A path (updated 2026-06-20)
- **Built + tested**: the enforcement core (`quorum-session.js`, `verifyQuorum`
  in JS/Python/Go), the `/try/multi-party` demo, the `attestationsToMembers`
  bridge (round-trip-tested), and migration 094 (additive, but see the
  correction above re subsystem).
- **Fielded on the Class-A path (done + verified)**:
  - Quorum policy persisted at issuance — `quorum_policy` written on the
    `guard.trust_receipt.created` after_state (`app/api/v1/trust-receipts/route.js`).
  - `canAccept()` early-reject gate in
    `app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js`
    (409 `quorum_signer_rejected` for a bad/duplicate/out-of-order signer).
  - `quorumGate()` consume gate in
    `app/api/v1/trust-receipts/[receiptId]/consume/route.js`
    (403 `quorum_not_satisfied` until the full trail holds; single-signoff
    challenges, `quorum_policy IS NULL`, skip the gate unchanged).
  - Quorum fan-out at `app/api/v1/signoffs/request/route.js` (one signoff per
    roster approver when a `quorum_policy` is present).
  - **Live multi-device E2E**: `e2e/multi-party-quorum.spec.js` — three virtual
    WebAuthn authenticators sign PO→AO→IG; consume returns 403 until all three
    sign, then 200. **PASSED.**
  - **Cross-language conformance**: 9 `EP-QUORUM-v1` vectors
    (`conformance/vectors/quorum.v1.json`) agree across JS / Python / Go
    (`node conformance/run.mjs`).
- The earlier `attest.js`/`consume.js` plan above is retained only as the
  bearer-subsystem reference; the Class-A wiring listed here is the shipped path.
- **Standards record**: the multi-party predicate is written up as the IETF
  companion draft `standards/draft-schrock-ep-quorum-00.md` and the preprint
  `docs/papers/ep-quorum-preprint.md`.
