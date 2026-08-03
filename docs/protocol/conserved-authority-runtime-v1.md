<!-- SPDX-License-Identifier: Apache-2.0 -->
# Conserved Authority Runtime v1

**Status:** same-team experimental runtime profile. This document composes
existing Gate contracts; it does not define a new wire protocol.

## 1. Purpose

The Conserved Authority Runtime lets one authorizer bound a fleet without
copying the root's authority into every child. Authority is transferred into
children and consumed at one credential-owning provider boundary.

The enforceable claim is deliberately narrow:

> Within one authoritative atomic state domain, a child cannot receive or
> consume more of the signed authority dimensions than the parent allocated,
> and Gate does not release a provider invocation when any required balance,
> occurrence, child-count, concurrency, status, or exact-action condition is
> unavailable.

This is not cross-cloud conservation, offline double-spend prevention, intent
verification, proof that every provider credential is mediated, or proof of an
external effect.

## 2. Composed contracts

| Concern | Gate contract | Enforced property |
| --- | --- | --- |
| Root authority | Authority registry/proof and authorization evidence | Exact relying party, subject, action scope, audience, authority head/epoch, validity, and revocation inputs. |
| Sibling allocation | `authority-allocation.ts` | Child action/audience containment, `cents` and `calls` aggregate conservation, `max_active_children`, exact authority-head pin, and atomic reservation ownership. |
| Per-action spend | `capability-receipt.ts` | Balance-valued parent authority, reserve-before-effect, one-way commitment, replay fencing, parent-funded child creation, and indeterminate charging. |
| Multi-action program | `bounded-execution-program.ts` | Signed DAG reachability, exact CAID/action or authenticated profile match, typed attempt budgets, total occurrence ceiling, and `max_concurrent_effects`. |
| Credential release | `admission-store.ts` and PostgreSQL RPCs | Current status, one-time execution right, resource reservation, provider-entry transition, and fail-closed refusal. |
| Uncertainty | Admission and capability reconciliation | `INDETERMINATE` prevents blind retry, retains consumed budget, and occupies a concurrency slot until authenticated reconciliation. |
| Fleet response | Status, supersession, revocation, reconciliation, reports | No new provider entry after suspension/revocation; already-entered uncertain work remains reconcilable rather than being rewritten. |

## 3. Limit types

The runtime keeps unlike safety quantities separate:

- **money or other consumables:** typed integer budget dimensions;
- **action attempts:** typed budget dimensions and per-node occurrence limits;
- **retained history:** `max_total_occurrences`;
- **active child allocations:** `max_active_children`;
- **open provider effects:** `max_concurrent_effects`;
- **compute:** a deployment-defined integer budget such as milliseconds,
  accelerator-seconds, or provider billing units.

An “LLM token” is not a universal safety unit. A deployment may use token count
as one compute dimension, but it does not replace money, occurrence,
concurrency, or exact-action limits.

## 4. Authority transfer

For every parent `p` in one authoritative state domain:

```text
reserved(p) + consumed(p) <= budget(p)
sum(registered direct-child allocations) <=
  sum(committed parent delegation operations)
```

Child creation is a parent spend:

1. construct and digest the exact child receipt;
2. reserve the delegated amount from the parent under one stable operation ID;
3. commit that reservation once with outcome `delegated`;
4. register the child only after the parent commitment is terminal.

The operation record binds the parent, child digest, amount, unit, scale,
scope, and validity. Reusing the operation ID for another child refuses.
Failure after parent commitment creates an orphaned but funded allocation; the
parent budget remains consumed until an authenticated remedy or reconciliation
path says otherwise. The runtime never silently refunds it.

## 5. Provider entry

A provider path protected by this profile must receive its invocation
capability only from the program-aware admission transition. Immediately before
entry, Gate rechecks:

1. current program and capability status;
2. exact authority and action bindings;
3. one-time execution-right ownership;
4. typed budget and occurrence availability;
5. active child-allocation limit;
6. open-effect concurrency limit; and
7. resource and credential-custody bindings.

If any check is unavailable, stale, mismatched, exhausted, suspended, revoked,
or indeterminate, the provider credential is not released.

For allowance-scoped execution, Gate captures the allowance revision and status
head at reservation, then MUST revalidate that exact assertion against the
current status row immediately before provider entry in the same atomic state
domain. Suspension, revocation, or supersession after reservation therefore
refuses entry. The reservation remains held for authenticated recovery or
expiry; refusal does not invent evidence that the provider was never entered.

Long-lived provider credentials should remain in Gate or a compatible
credential broker. CB4A-style proxy and short-lived-token patterns can supply
that custody layer. Condition-bounded workload keys can strengthen live-key
use for stable attestable workloads. Neither composition expands the
conservation claim beyond the atomic domain Gate actually controls.

## 6. Suspension, revocation, and coverage

Fleet-wide suspension or revocation blocks new reservations and provider
entry. It does not erase work that may already have crossed the effect
boundary. `INVOKING` and `INDETERMINATE` records remain visible until
authenticated reconciliation records a terminal provider outcome.

Signed program reports expose retained Gate-recorded occurrence state and
budget use. Coverage reconciliation can compare declared effect sources with
Gate records, but supplied-population reconciliation is not proof that no
unseen provider path exists. The passive scanner is therefore a deployment
prerequisite: it discovers ambient credentials, agent-writable policy, and
unmediated provider routes before anyone claims containment.

## 7. Atomic-domain limitation

The runtime requires the parent, all authority-bearing ancestors and
descendants, allocation snapshots, reservations, execution rights, and
provider-entry transition to share one authoritative atomic state domain.

Two independent stores can each accept the same signed root and each allocate
its full balance. The reference tests preserve this as an explicit
counterexample. A deployment spanning independent clouds, disconnected
devices, or offline replicas must either select one online authority domain or
state that aggregate conservation is not guaranteed.

## 8. Evidence level

The repository provides:

- TypeScript memory and PostgreSQL implementations;
- deterministic syntax and transition vectors;
- hostile concurrent sibling, replay, orphan, concurrency, and state-fork
  tests; and
- bounded TLA+ model checking over one root, three possible children, and
  three delegation operations.

These are same-team implementation, regression, and bounded-model evidence.
They are not an independent implementation, an unbounded proof, a
TypeScript-to-TLA+ refinement proof, or production deployment evidence.
