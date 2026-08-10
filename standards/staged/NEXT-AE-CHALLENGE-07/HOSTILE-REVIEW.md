# Hostile review of AE-CHALLENGE-06 and the -07 candidate

Date: 2026-08-10

This is an internal review record. It is not an Internet-Draft upload artifact
and does not claim independent review.

## Confirmed defects repaired in the -07 candidate

### Critical

1. **Nonce claim and capacity were separate operations.** Two concurrent
   copies could both reserve before one won the nonce, while claim-first order
   could burn a nonce when capacity refused. The candidate replaces both
   orders with one owner-side transition covering expiry, exact-body claim,
   collision classification, and every applicable cap bucket.
2. **The durable runtime consumed before checking presentation action.** An
   approve-A/present-B attempt could destroy the valid A challenge. The runtime
   now rejects unsupported or action-mismatched presentations before the
   single-use state transition, with a regression proving the original A
   presentation remains usable.

### High

3. **The replay key included correlation-only `challenge_id`.** One issuer
   could reuse a nonce under another challenge identifier. The v2 runtime key
   is nonce-only inside one issuer-scoped store. Its namespace and mandatory
   drain-or-atomic-migration rule are explicit.
4. **Replay and expiry had no precedence rule.** Expiry-first processing could
   hide a duplicate while the first claimed evaluation was still in flight.
   Retained claimed state now classifies replay or collision before expiry;
   expiry applies only to an otherwise open or absent claim.
5. **Issuer aliases could split replay state.** Each binding must now define a
   stable authenticated issuer identity, and every alias or replica that can
   validate the same challenge must map to that identity and replay domain.
6. **The core JSON object was not closed enough for interoperability.** The
   candidate now defines required members, JSON types, SHA-256 wire syntax,
   URI requirements, predicate and hint structure, and optional members.
7. **Action-profile semantics could drift under one URI.** The relying party
   must pin immutable profile semantics for the challenge lifetime.
8. **The returning presenter was not clearly bound to `audience`.** Presenter
   authentication and the profile-defined audience comparison now precede
   nonce claim. Transferable or anonymous profiles must define the exception.
9. **Retry timing could schedule only expired attempts.** `not_before` plus
   maximum jitter must remain strictly before `expires_at`; conflicting HTTP
   and core lower bounds that reach expiry suppress submission.
10. **A global cap could be over-allocated by independent shards.** Every cap
    bucket shares the claim transaction or uses bounded preallocated quotas.
11. **Recovered reservations lacked a stale-worker rule.** Finalization and
    follow-up publication require an ownership fence after reassignment.

### Medium

12. Duplicate JSON names and unbounded parsing could create ambiguous body
    digests or pre-claim denial of service. Both are now refused or bounded
    before expensive work.
13. Obtain hints could become SSRF or credential-forwarding instructions.
    Independent endpoint, redirect, credential, and disclosure policy is now
    required.
14. Follow-ups could inherit a stale action or policy. They now rederive the
    current proposed action and live requirements.
15. HTTP did not distinguish a fresh evidence challenge from replay,
    collision, expiry, capacity refusal, or owner unavailability. The
    `ae-required` type is now limited to a genuinely fresh challenge; hard-cap
    and owner failures use 503 without policy detail, while disclosed state
    conflicts may use 409 without a replacement challenge.
16. The KLRC citation misnamed Jeff Lombardo and used the wrong publication
    date. The reference now matches the live Datatracker record.
17. The core did not define whether evidence entries, profiles, and predicates
    were conjunctive or alternative. Every required-evidence entry and every
    predicate is now conjunctive; profiles within one entry are alternatives.
18. Pre-transition validation and the atomic transition both appeared to own
    stateful body comparison, making `body-collision` unreachable under one
    reading. The owner transition now exclusively decides authoritative body
    equality and collision; a front-end cache cannot preempt that result.
19. The transition relied on a complete-body digest but stateful issuance did
    not define how to compute it across JSON reserialization or non-JSON
    mappings. Every binding or profile now pins one deterministic complete-body
    digest procedure covering core, extension, and unknown members.
20. The examples violated the draft's own nonce and digest requirements, and
    unbounded JSON integers could produce cross-language precision differences.
    The examples are now syntactically conformant and both integer fields have
    the portable range 0 through 2147483647.

## Evidence added

- The lifecycle model checks that action mismatch is inert and includes a
  mutation that consumes before action agreement.
- A focused finite model checks the compound owner transition, duplicate
  reservation, nonce burn, expiry/replay precedence, owner uncertainty,
  cross-shard cap conservation, stale-owner fencing, retry bounds, and
  audience binding. Every listed unsafe ordering has an explicit
  counterexample.
- Runtime regressions cover action mismatch and nonce reuse under another
  `challenge_id`.

## Deliberately unclaimed

The focused model is same-team finite logic evidence, not a database
linearizability or implementation-refinement proof. It does not model
stateful-open registration or transfer of an existing outstanding-state debit.
The reference runtime does not yet implement the compound capacity transition,
self-describing issuance, hard-cap buckets, fenced recovery, raw-JSON duplicate
rejection, the separately held current-action input, or several strict -07
identifier requirements. The draft labels every one of those gaps. No
independent implementation or interoperability result is claimed.
