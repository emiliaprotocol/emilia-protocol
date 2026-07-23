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
- server-selected tenant, provider, provider account, environment, and executor;
- the canonical material action, its JCS SHA-256 digest, and its CAID;
- the Receipt Required challenge and pinned `EP-APPROVAL-v1` endpoint;
- the AEB requirement, complete pinned-configuration digest, and a
  server-derived consumption nonce bound to the operation; and
- creation and expiry instants; and
- a server-held HMAC over the complete closed proposal, used only as an
  integrity seal and never as transferable authority.

It deliberately contains no public signature, `authorized` flag, or reusable
permit. Its HMAC proves only that this relying-party service produced the exact
short-lived request; it does not authorize the effect.
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
   registry, adapters, mapping profiles, trust roots, expected action, exact
   executor, and server-resolved authenticated current status. Presenter status
   objects are ignored.
3. The evaluation binds the same operation, initiator, requirement, CAID, and
   AEC composition digest and is `SATISFIED`.
   The evaluation's consumption nonce MUST equal the proposal nonce, preventing
   a second evaluation for the same proposal from creating a new reservation.
4. Its requirement contains the mandatory `one-time-consumption` term.
5. Gate independently authorizes the presented `EP-RECEIPT-v1` against the
   observed action and local policy. The resolved Gate requirement MUST be
   explicitly receipt-required; Gate's normal unguarded pass-through result is
   a profile configuration failure here.
6. A durable, ownership-fenced, permanent-consumption store atomically reserves
   the AEB operation and every native protocol replay unit.
7. A separate durable consequence-attempt store reserves a server-generated
   attempt ID and exact tenant/provider/account/environment/request binding,
   then advances it by owner-fenced compare-and-swap before invocation.

Evidence satisfaction and local authorization remain separate decisions.
`SATISFIED` never implies `AUTHORIZED`, and a valid human receipt cannot bypass
the relying party's Gate policy.

## Failure and reconciliation

- Missing, stale, revoked, uncheckable, or unsatisfied evidence cannot invoke
  the effect.
- A Gate refusal releases the operation reservation because the effect was not
  called.
- After a successful effect, the AEB replay fence becomes permanently consumed
  before the consequence attempt is marked `COMMITTED`. If consumption cannot
  be confirmed, the attempt remains `INDETERMINATE` and repairable; the system
  never creates a terminal effect record paired with reusable authority.
- Once the effect callback is invoked, an exception is `INDETERMINATE`; both
  the AEB and consequence-attempt reservations remain frozen and a fresh
  receipt cannot cause a blind replay.
- If the effect executed but post-effect evidence or AEB commit failed, the
  operation remains reserved for reconciliation. It is never released merely
  because bookkeeping failed.
- Reconciliation accepts only an injected, relying-party-owned verifier for
  authenticated provider evidence bound to the exact operation, attempt,
  request, tenant, provider, provider account, environment, CAID, and
  normalized action digest. One atomic attempt-store transition binds the
  evidence digest and selects the terminal state. `COMMITTED` consumes the operation;
  `NOT_COMMITTED` releases it for an explicit retry.
- A terminal consequence paired with a still-reserved AEB row (for example,
  from a legacy deployment or a lost database acknowledgement) is repaired by
  `repairAeb`. Repair never invokes an effect: it re-verifies the signed AEB
  record, reads the complete durable attempt binding, and converges only a
  stored `COMMITTED` or `RELEASED` terminal state. Restart repair may claim the
  AEB reservation only through the store's configured recovery authorizer.
- Opaque attempt-owner capabilities are not enumerable response or error data.
  A same-process caller can retrieve the handle only from the exact returned
  object; after restart, the durable store performs separately authorized,
  fenced owner rotation.
- Restart recovery rotates the opaque owner capability. A recovered
  `INVOKING` attempt becomes `INDETERMINATE`; recovery is never evidence that
  the provider did not execute, and the stale owner cannot transition it.
- The PostgreSQL profile requires separate executor and recovery credentials,
  tenant-to-database-principal bindings, and disjoint RPC grants. Recovery is
  lease-stale-only, includes abandoned `RESERVED` attempts, and cannot be
  invoked by the executor or Supabase `service_role` credentials.

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
- `@emilia-protocol/gate/proposal-to-effect-postgres`
- `packages/gate/src/proposal-to-effect.ts`
- `packages/gate/src/proposal-to-effect-postgres.ts`
- `packages/gate/proposal-to-effect.test.ts`
- `conformance/vectors/proposal-to-effect.v1.json`
- `examples/proposal-to-effect/demo.mts`

The demo stores are intentionally in-memory. Production deployments use the
PostgreSQL AEB consumption and consequence-attempt stores, an authenticated
`EP-STATUS-v1` verifier backed by relying-party-held status heads, and an
authenticated provider-evidence verifier for reconciliation.
The AEB store requires separate tenant-bound executor and recovery database
logins and exposes only narrow functions; `service_role` has no table or RPC
authority. The remedy store is independently tenant-bound and RPC-only. These
credential boundaries are part of the production profile, not optional
hardening.
