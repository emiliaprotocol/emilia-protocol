<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reliance Risk Plane v1

**Status:** reference architecture and implementation contract. It is not an
insurance product, legal opinion, coverage decision, solvency assertion,
adjudication service, or payment rail.

The Reliance Risk Plane adds four bounded questions around the existing EMILIA
consequence lifecycle without collapsing them into authorization:

1. **What responsibility terms did named parties sign?** A separately signed
   `EP-LOSS-ALLOCATION-SCHEDULE-v1` is pinned to the exact Reliance Program.
2. **How much unresolved exposure is open now?** The Open Exposure Ledger
   atomically reserves before the effect and keeps uncertain effects open.
3. **What exact action was refused, and why?** An
   `EP-ACTION-REFUSAL-STATEMENT-v1` binds the refusal to CAID, action digest,
   program, requirements, nonce, delivery custody, and time.
4. **Did the declared system-of-record population reconcile to the declared
   receipt population for a bounded period?** A signed coverage reconciliation
   attestation records the supplied roots and join counts. It never self-proves
   that the supplied populations were complete.

These objects are independent evidence legs. None can replace the existing
authorization decision.

```text
customer-owned Reliance Program
  -> pinned evidence profiles
  -> CAID / action match
  -> evidence SATISFIED or refusal statement
  -> AEB + local policy AUTHORIZED or REFUSED
  -> atomic exposure reserve (portfolio ceilings)
  -> one provider invocation
  -> EXECUTED / PROVEN_NOT_EXECUTED / INDETERMINATE
  -> independent reconciliation and closeout
  -> bounded-period coverage reconciliation
  -> governed-taxonomy census with primary suppression + externally reported loss feed
```

## The non-collapsing state axes

| Axis | Question | What it cannot prove |
|---|---|---|
| `VERIFIED` | Did a native verifier validate the artifact? | acceptance, sufficiency, authorization, execution |
| `MATCH` | Does it bind the same material action? | evidence sufficiency or authority |
| `SATISFIED` | Did the relying party's pinned evidence requirement pass? | authorization or execution |
| `AUTHORIZED` | May this exact action proceed under local policy now? | provider receipt or observed effect |
| `RESERVED` | Was portfolio exposure capacity atomically held? | authorization or execution |
| `INDETERMINATE` | Did custody transfer without authenticated outcome evidence? | success, failure, release, or retry safety |
| `RECONCILED` | Did an independent authority accept authenticated outcome evidence? | legal causation or coverage |
| `COVERED_POPULATION` | Did two supplied period populations reconcile? | that either supplied population was complete |

## Loss Allocation Schedule

The schedule is a demand-side, relying-party artifact. It is signed separately
and bound to `program_id`, `version`, `source_digest`, and `program_digest`.
The Reliance Program v1 source remains closed; the schedule enters through a
digest-pinned Admissibility Profile reference. This avoids creating a second
policy dialect or pretending a technical schema creates a legal contract.

Verification proves the signed bytes, issuer pin, exact program binding,
validity/status, and complete non-conflicting allocation rules. It does not
prove that a court will enforce the terms, that a named party is solvent, that
a loss is covered or caused, or that money will move.

## Open Exposure Ledger

Exposure is reserved before provider entry. Limits can be scoped to tenant,
program, counterparty, and action class for a bounded currency/window. The
reserve and aggregate-limit check are one linearizable operation.

`INVOKING` and `INDETERMINATE` remain open exposure. A timeout never releases
the reservation and never creates a retry right. Only the separately
authenticated reconciliation authority can accept provider/outcome evidence
and close or continue the exposure. Origin, executor, and reconciler identities
are distinct.

The ledger measures declared exposure. It is not a carrier balance sheet and it
does not determine legal loss.

## Action Refusal Statement

The statement is transaction-time evidence for one technical refusal. It binds
the exact CAID/action, Reliance Program, failed requirement IDs, evidence and
challenge digests, nonce, expiry, semantic axes, issuer, and delivery custody.
Replay-checked acceptance consumes the nonce once.

It is not a benefit determination, legal denial, authorization, or proof that a
human understood the refusal. `draft-sabey-refusal-transparency` remains
authoritative for its probe-run semantics; SCITT refusal-event profiles remain
authoritative for their event domains. EMILIA maps those inputs and does not
reinterpret them as this transaction-time object.

## Coverage reconciliation and census

A coverage reconciliation attestation signs:

- the bounded period and pinned program;
- the existing declared-surface coverage report hash;
- the exact governed receipt census digest;
- system-of-record and receipt inventory identifiers, roots, and counts;
- conserved join counts for matches, bypasses, orphans, uncertainty,
  exclusions, and declared exceptions; and
- optional external timestamp evidence.

The signer asserts the supplied populations. Population completeness requires
separate system-of-record evidence and cannot be inferred from this artifact.

The reference coverage runner adds the missing derivation boundary before the
attestation. Each source operator signs a root over privacy-minimized
`record_id`, `caid`, `action_digest`, and closed classification records. The
relying party pins both source identities and mapping-profile digests, verifies
the independently signed populations, rejects ambiguous identity mappings, and
then derives all six conserved join counts. The Da Vinci PAS reference
connector retrieves server-observed FHIR state by opaque reference and
recomputes the exact action; a public caller cannot supply the action identity.
This closes the reference implementation loop while preserving the same honest
boundary: a signed root of supplied records does not prove source completeness.

The Receipt Census emits only aggregate buckets whose action and outcome labels
belong to a relying-party-pinned closed taxonomy and whose counts meet a
configured minimum. Suppressed buckets are disclosed only as aggregate counts.
No raw action, receipt, patient, member, or other payload belongs in the census.
The implementation does not detect identifiers encoded inside an allowed
taxonomy string; safe taxonomy vocabulary remains a relying-party control.
This is coarse primary suppression, not differential privacy: it does not by
itself prevent differencing, complementary-cell disclosure, repeated-query
attacks, or an untruthful source inventory. Deployments releasing overlapping
censuses need separate query budgets, secondary suppression, and access audit.

Loss-experience corrections are accepted only through a relying-party-owned
atomic lineage transaction. The store locks/loads the exact digest-bound
current predecessor heads, runs EMILIA's validator before mutation, and commits
all successors only when every reporter, relying-party, program, receipt,
action-class, currency, and opaque-lineage binding passes. One predecessor can
therefore produce at most one accepted current successor. Loss-experience
records still carry externally reported facts and provenance; EMILIA does not
infer causation, coverage, adjudication, or amount.

## Carrier-readable action composition

The risk-plane components stay separate, but a reviewer needs one bounded way
to ask whether the required technical evidence exists for one exact action.
Two additive artifacts provide that view without creating insurance semantics:

1. `EP-ACTION-RISK-CONTROL-SCHEDULE-v1` is a separately signed technical
   requirements schedule. It pins the action class, CAID profile, and provider
   path, qualification
   freshness, control-program digests, complete-mediation evidence references,
   exposure ceilings, reconciliation authority, outcome-source requirements,
   and treatment of divergent or indeterminate results. Its only evaluation
   values are `ELIGIBLE`, `NOT_ELIGIBLE`, and `INDETERMINATE`.
2. `EP-ACTION-EVIDENCE-PACKET-v1` is a content-addressed manifest for one
   action. It binds the schedule evaluation to the supplied qualification,
   authorization, admission, exposure, provider, observed-effect, population,
   and optional loss or recourse artifacts. The verifier recomputes attachment
   digests and orchestrates the relying party's chosen native verifiers. Those
   callbacks are trust inputs and must independently validate digest, subject,
   state, and currentness; an echo callback is not evidence. Its only
   conclusions are `TECHNICALLY_COMPLETE`, `INCOMPLETE`, `CONFLICTED`, and
   `INDETERMINATE`.

The v1 schedule pins its issuer and qualification-status authority. Native and
provider trust roots, current status, source independence, and verifier choices
come separately from the reviewer. A packet cannot make its own signer trusted
or establish schedule-to-adapter key agreement. A complete packet does not
establish population completeness, physical-world causation, legal liability,
policy coverage, claim acceptance, solvency, or payment.

## Rollout and blast radius

A production Reliance Program version needs an explicit canary cohort,
percentage, maximum active-version concentration, blast-radius ceiling,
supersession reason/effective time, and a customer-owned degraded-mode policy.
The only v1 degraded modes are:

- `fail_closed`;
- `manual_hold`; and
- `observe_only`, only when the customer policy explicitly permits it for that
  action class.

Terminal action history is never rewritten by a program supersession.

## Assurance

`formal/reliance-risk-plane.model.mjs` exhaustively explores 16,384 bounded
states over eleven independent obligations. Each obligation has a deliberately
unsafe single-guard variant and a concrete counterexample. This is a finite,
same-team model: database linearizability, cryptography, identity proofing,
legal enforceability, solvency, causation, payment, and source-population
completeness remain outside its claim.
