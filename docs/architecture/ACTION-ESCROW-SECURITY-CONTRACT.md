<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Action Escrow Security Contract

**Status:** public implementation contract; not a deployment or standardization claim

**Profile family:** `EP-ACTION-ESCROW-*`

**Product boundary:** EMILIA coordinates evidence and technical enforcement. A
separately selected provider holds or moves funds; this contract does not prove
that provider's licensing, suitability, solvency, or jurisdictional authority.

## Purpose

Action Escrow maps an executed agreement to an exact, technically gated machine
action without treating a signed PDF, an approval, or a provider status as
interchangeable evidence. Technical gating under this profile is not a claim
that the agreement, release, or remedy is legally enforceable.

The first profile is a contractor milestone release:

1. the parties execute a final document;
2. a signed Document-to-Action Binding maps that exact document and its material
   terms to an exact release action;
3. every required party separately approves that exact release action;
4. a configured custodian or payment provider reports that the matching funds
   are available under a separately authenticated adapter;
5. the release engine reserves the one permitted effect, invokes the custodian
   with a stable idempotency key, and reconciles the result;
6. both parties receive the same portable evidence manifest.

The human-facing rule is: **Both sides approve the exact release before the
configured path may proceed.** This describes the technical control, not legal
adjudication or guaranteed provider performance.

## Three Independent Proofs

The implementation MUST keep these artifacts separate and join them by digest.

### 1. Document Execution

An e-sign provider can establish that its workflow reached a named state and
return the final document bytes and participant metadata. A webhook is only a
notification. The verifier MUST fetch the authoritative final bytes, hash them,
and compare that digest to the Document-to-Action Binding.

Document execution alone MUST NOT authorize a payment.

### 2. Exact-Action Approval

Each required party supplies a pinned, device-bound resolution over the exact
release action and current binding. Approval, decline, amendment, and rejection
remain distinct outcomes. Only an approval under the complete relying-party
profile may authorize the action.

An approval for an earlier binding, a different amount, a different
destination, or a superseded amendment MUST NOT authorize release.

### 3. Custodian Effect

Funding and release state come from a separately authenticated custodian
adapter. EMILIA MUST NOT claim to hold funds, be an escrow agent, or infer a
provider's licensing status from an API response. Deployers are responsible for
provider and jurisdiction diligence.

The provider call is an external effect. A timeout or lost response after the
call begins is `release_indeterminate`, not proof that release failed.
`release_indeterminate` is Action Escrow's fenced owner result: it preserves
single ownership of the release attempt while the provider effect is unknown.
It is not an irreversible terminal state, an execution-success claim, or a
retry grant. The durable reservation remains closed to another release call
even if the original provider response arrives later. While the effect is
indeterminate, `reconciled_at`, `provider_statement`, and
`provider_verification` remain empty. EMILIA sets them only from an
authoritative provider read whose transport is authenticated and whose
statement verifier authenticates and binds the evidence to the exact provider,
idempotency key, request, transaction, milestone, amount, currency,
destination, agreement, document binding, and release action. Failed
authentication leaves the release indeterminate. Authenticated `released`
evidence closes the owner result as released; authenticated `not_released`
evidence may return the state to the applicable pre-release path without
pretending that the uncertainty never existed.

## Signed Document-to-Action Binding

`EP-DOCUMENT-ACTION-BINDING-v1` binds:

- the final document SHA-256 digest, media type, and byte length;
- canonical structured material terms;
- the exact parties and their roles;
- the required approval roster;
- milestone identifiers, amounts, and acceptance rules;
- the exact release action digest or closed release template;
- validity and amendment/supersession rules;
- the agreement and binding identifiers.

The binding verifier MUST use relying-party-pinned, role-scoped keys. Embedded
keys and provider labels carry no authority. Money values are decimal strings,
never JSON numbers.

## Amendment Rule

An amendment is a new binding, not a mutable field on the old one.

- The new binding names the exact prior binding it supersedes.
- All required parties approve the new binding and affected release action.
- Once the new binding is effective, any unexecuted authorization under the old
  binding is permanently ineligible.
- An amendment racing a reserved release leaves the release indeterminate until
  the custodian is reconciled. It never silently rewinds the effect.

## Release State Machine

The production state backend MUST be durable and provide atomic compare-and-swap
semantics. In-memory state is allowed only behind an explicit demo/test option.

The closed states are:

`draft`, `awaiting_acceptance`, `effective`, `awaiting_funding`, `funded`,
`milestone_submitted`, `release_reserved`, `released`, `disputed`,
`amendment_pending`, `cancelled`, `completed`, and
`release_indeterminate`.

The release key is derived from the agreement, current binding, milestone, and
exact release action. It is not supplied by the presenter.

The effect sequence is:

1. atomically reserve the release;
2. durably record the exact provider request and stable idempotency key;
3. invoke the configured custodian;
4. authenticate and reconcile the provider's authoritative state;
5. atomically commit `released`, return to the applicable pre-release state on
   authenticated `not_released` evidence, or fence the owner result as
   `release_indeterminate`.

No path automatically retries an indeterminate release. The only permitted
advance is an authenticated reconciliation of the same provider operation and
idempotency key.

## Milestone Evidence

Milestone evidence proves only that named evidence was supplied and evaluated
under the pinned acceptance rule. It does not prove workmanship, physical
truth, legality, safety, or contractual enforceability.

Where the agreement requires a human decision, the relevant party approves,
declines, amends, or rejects the milestone resolution. A machine classifier may
support review but cannot silently fill a required human-approval role.

A comparison verdict says only how named evidence compares under a pinned
profile. It is not a provider execution outcome. Likewise, if a later review
marks a receipt assessment `overturned`, the assessment is superseded; neither
the receipt bytes nor an external release is reversed.

## Closed-Loop Remedy Composition

Action Escrow owns the release-effect claim downstream of Gate. Gate remains the
policy and enforcement controller that fences one owner claim; it does not move
funds. The Gate claim token presented to the selected Action Escrow worker is a
bearer capability and must be protected as a secret; it is not worker identity,
payment authority outside the bound claim, or legal entitlement. A dispute
records a bounded challenge to an observed release and remains separate from any
decision about remedy. Revocation before Gate issues the release claim can
prevent that claim. Revocation learned after claim or effect is late: it may
constrain future authority and support a dispute, but it cannot rewrite the
original release record.

Every refund, clawback request, replacement release, or other remedy is a fresh
compensating action. It requires a new CAID, action digest, operation ID,
authorization, owner claim, provider result, and evidence record. A remedy may
offset an original effect; it does not mutate or reverse the original effect in
the evidence history. See
[Lifecycle and Remedy Kernel](./LIFECYCLE-REMEDY-KERNEL.md).

## Portable Evidence Package

`EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1` contains or references:

- the final document digest and byte length;
- the verified Document-to-Action Binding;
- each required party's exact-action resolution;
- authoritative funding evidence;
- milestone evidence and its resolution;
- the release reservation, provider request reference, and released,
  not-released, or fenced-indeterminate owner result;
- amendment and supersession history;
- the relying party's verification profile and trust-root identifiers;
- a deterministic content digest and explicit limitations.

The package is a reproducible evidence manifest, not a legal opinion. A package
digest does not upgrade an invalid component.

## Required Negative Properties

The implementation and hostile suite MUST refuse:

1. changed document bytes under the old binding;
2. changed structured terms under the old document;
3. amount, currency, destination, milestone, or action substitution;
4. a missing, duplicate, unknown, or wrong-role party;
5. provider-complete status presented as party approval;
6. embedded or cross-role signing keys;
7. approval of an earlier or superseded binding;
8. self-approval where separation of duties is required;
9. unsigned or presenter-selected milestone acceptance;
10. a webhook presented as authoritative provider state;
11. duplicate delivery and concurrent release;
12. retry after an ambiguous provider response;
13. rollback, stale-read, or compare-and-swap loss;
14. mutation of caller-owned objects after signing or packaging;
15. malformed dates, decimal numbers, Unicode, JSON aliases, unknown fields,
    oversized inputs, and hostile values that attempt to make a verifier throw.

## Claim Boundary

Action Escrow can produce verifiable evidence that pinned parties approved exact
bytes and that a configured executor applied a closed state machine to a
custodian call. That is a technical-control claim, not a legal-enforcement
claim. It does not prove:

- civil identity without the relying party's enrollment process;
- comprehension, voluntariness, or absence of coercion;
- document enforceability;
- quality or physical completion of work;
- provider licensing or solvency;
- that no payment path existed outside the integrated custodian;
- finality while the provider outcome is indeterminate;
- that a comparison verdict is an execution outcome;
- that an overturned receipt assessment reversed a receipt or external effect;
- adjudication of a dispute or legal enforceability of a remedy; or
- production deployment, independent conformance, or adoption as a standard.

The technical assurance is exactly as strong as complete mediation at the
custodian release boundary and the relying party's pinned trust roots.
