<!-- SPDX-License-Identifier: Apache-2.0 -->
# Proposal-to-Effect Profile v1

The Proposal-to-Effect profile is a product orchestration contract over
existing EMILIA components. It turns an agent's proposed consequential action
into an exact, human-authorized, evidence-satisfied execution without creating
a second bearer credential.

This profile is **not** a new authorization-receipt format and a proposal is
**not** authority. The authority artifact remains `EP-RECEIPT-v1`; CAID names
the material action; AEB evaluates relying-party-pinned evidence; and Gate
owns local authorization, one-time receipt consumption, effect invocation, and
execution evidence.

## Flow

```text
authenticated agent request
        |
        v
server canonicalizes action + derives CAID
        |
        v
EP-APPROVAL-v1 ----> human approval ----> EP-RECEIPT-v1
        |                                      |
        +------------------+-------------------+
                           v
                  signed AEB evaluation
                           |
                           v
                  Gate policy preflight
                           |
                           v
              durable operation reservation
                           |
                           v
                     exact effect call
                    /                 \
              COMMITTED          INDETERMINATE
                  |                    |
          consume operation     keep reservation frozen
                                       |
                              authenticated reconciliation
```

The acquisition rail is the existing `EP-APPROVAL-v1` contract. An agent posts
the challenged action to the pinned authorization endpoint, receives a pending
request and approval URL, polls with the returned opaque token, and retries
with the resulting `EP-RECEIPT-v1`. Endpoint origin, redirects, response size,
strict JSON parsing, request authentication, and poll-token handling are
enforced by `@emilia-protocol/require-receipt`.

## Proposal contract

`EMILIA-PROPOSAL-TO-EFFECT-v1` is a short-lived, closed request object produced
by the relying-party application. It contains:

- server-selected profile, operation, and authenticated initiator identifiers;
- the canonical material action, its JCS SHA-256 digest, and its CAID;
- the Receipt Required challenge and pinned `EP-APPROVAL-v1` endpoint;
- the AEB requirement, complete pinned-configuration digest, and a
  server-derived consumption nonce bound to the operation; and
- creation and expiry instants.

It deliberately contains no signature, `authorized` flag, or reusable permit.
A caller MUST NOT treat possession of the proposal as authorization. On every
execution attempt the implementation reruns the relying-party-owned
canonicalizer and compares the proposal against the local profile.

The canonicalizer, CAID derivation, selector, required-field set, acquisition
endpoint, and AEB requirement come from local configuration. Presented data
cannot select or replace them. Multi-tenant services MUST use tenant-scoped AEB
relying-party configurations or include the tenant identifier among the
profile's material required fields.

## Admission and execution

Execution requires all of the following:

1. The proposal is unexpired and re-canonicalizes to the same action, action
   digest, and CAID.
2. The signed `AEB-EVALUATION-v1` record verifies under the pinned evaluator,
   registry, adapters, mapping profiles, trust roots, and current status.
3. The evaluation binds the same operation, initiator, requirement, CAID, and
   AEC composition digest and is `SATISFIED`.
   The evaluation's consumption nonce MUST equal the proposal nonce, preventing
   a second evaluation for the same proposal from creating a new reservation.
4. Its requirement contains the mandatory `one-time-consumption` term.
5. Gate independently authorizes the presented `EP-RECEIPT-v1` against the
   observed action and local policy. The resolved Gate requirement MUST be
   explicitly receipt-required; Gate's normal unguarded pass-through result is
   a profile configuration failure here.
6. A durable, ownership-fenced, permanent-consumption store reserves the AEB
   operation before the effect is invoked.

Evidence satisfaction and local authorization remain separate decisions.
`SATISFIED` never implies `AUTHORIZED`, and a valid human receipt cannot bypass
the relying party's Gate policy.

## Failure and reconciliation

- Missing, stale, revoked, uncheckable, or unsatisfied evidence cannot invoke
  the effect.
- A Gate refusal releases the operation reservation because the effect was not
  called.
- A successful effect commits both Gate's receipt lifecycle and the AEB
  operation lifecycle.
- Once the effect callback is invoked, an exception is `INDETERMINATE`; the AEB
  reservation remains frozen and a fresh receipt cannot cause a blind replay.
- If the effect executed but post-effect evidence or AEB commit failed, the
  operation remains reserved for reconciliation. It is never released merely
  because bookkeeping failed.
- Reconciliation accepts only an injected, relying-party-owned verifier for
  authenticated provider evidence bound to the exact operation, CAID, and
  normalized action digest. `COMMITTED` consumes the operation;
  `NOT_COMMITTED` releases it for an explicit retry.

## Upstream evidence

PSEA, OAuth transaction confirmation, delegation receipts, workload identity,
payment mandates, and other systems may supply native evidence legs through
the AEB adapter contract. They are optional inputs, not product dependencies.
Each native artifact keeps its own verifier and claims. AEB pins the adapter,
trust roots, mapping profile, evidence role, freshness policy, and requirement;
the profile never upgrades "human present," delegation, authentication, or
policy evidence into authorization by itself.

## Reference implementation

- `@emilia-protocol/gate/proposal-to-effect`
- `packages/gate/src/proposal-to-effect.ts`
- `packages/gate/proposal-to-effect.test.ts`
- `conformance/vectors/proposal-to-effect.v1.json`
- `examples/proposal-to-effect/demo.mts`

The test and demo stores are intentionally in-memory. Production use requires
a durable store that satisfies the AEB and Gate store contracts, plus an
authenticated provider-evidence verifier for reconciliation.
