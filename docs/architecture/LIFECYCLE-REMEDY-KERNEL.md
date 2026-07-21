<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Lifecycle and Remedy Kernel

**Status:** private implementation-aligned architecture contract; not a
deployment, conformance, or standardization claim

**Profile discriminator:** `EP-GATE-REMEDY-PROGRAM-PROFILE-v1`

**Reference API:** `packages/gate/src/remedy-program.ts`

This document defines the closed-loop terminology shared by Gate Trust
Programs, Receipt Programs, Action Escrow, and Recourse References. The profile
coordinates technical policy, evidence, effect ownership, and compensating
actions. It does not adjudicate disputes, reverse external reality, move funds
by itself, or make a contract or remedy legally enforceable.

## 1. Non-Negotiable Invariants

1. **The original effect is immutable.** Once an effect is observed or its
   result is indeterminate, later evidence may add context, reconciliation,
   assessment, dispute, decision, or compensation records. It never edits the
   original action, operation, owner result, receipt, or effect record.
2. **Revocation has a claim boundary.** Before an effect claim, Gate revalidates
   current authority and can refuse the claim. After a claim or effect,
   revocation is late: it constrains future authority and may support dispute or
   remedy policy, but it does not undo the original effect.
3. **A dispute is not a decision.** A dispute records who challenged which exact
   effect, with what evidence, when, and for what bounded remedy. A separately
   authorized decision either permits a bounded compensating action or closes
   the case without remedy.
4. **Every remedy is a fresh compensating action.** It has a new CAID, action
   digest, operation ID, authorization, claim, downstream owner, result, and
   evidence. It may offset an original effect; it never reuses or rewrites it.
5. **Gate controls policy and enforcement, not the external effect.** Gate owns
   evidence admission, state progression, current-authority checks, claim
   fencing, and remedy limits. Receipt Program or Action Escrow owns the selected
   downstream effect claim and owner result.
6. **A claim token is a bearer capability.** The holder can submit the bound
   owner result. The token is not identity, a receipt, recourse evidence, or a
   legal entitlement.
7. **Uncertainty stays fenced.** An indeterminate owner result blocks blind
   replay but remains open to authenticated reconciliation of the same
   operation. It is not a permanent assertion that the effect happened or did
   not happen.
8. **Evidence labels do not collapse layers.** A comparison verdict is not an
   execution outcome. An overturned receipt assessment changes the assessment,
   not the receipt or external effect. Recourse is signed evidence of a
   commitment, not adjudication.

## 2. Component Ownership

| Component | Owns | Does not own |
| --- | --- | --- |
| Gate / Trust Program | Policy evaluation, evidence admission, stage state, pre-claim revocation checks, atomic claim fencing, remedy authorization limits | Provider entry, external effect, legal decision, or external effect reversal |
| Receipt Program | One bounded instruction's downstream effect claim, executor invocation, owner result, and certificate evidence | Gate policy, adjudication, or mutation of an earlier receipt/effect |
| Action Escrow | One governed release-effect claim, provider idempotency binding, owner result, and authenticated release reconciliation | Funds, provider licensing, legal escrow status, or dispute adjudication |
| Remedy Program | Post-effect case state, late-revocation evidence, dispute record, bounded compensating-action authorization, claim fencing, and remedy accounting | Rewriting the original effect, deciding law or coverage, or executing the provider effect itself |
| Recourse Reference | Signed, action-bound evidence of a named party's stated commitment and terms | Coverage decision, solvency, adjudication, payment, or effect ownership |
| External provider or decision-maker | The provider's actual effect or the authorized external decision under its own rules | Authority merely because EMILIA can verify a related artifact |

The owner split is exclusive for one operation. Gate selects either
`receipt-program` or `action-escrow`; both cannot own the same effect claim.
Selecting an owner and issuing a claim are controller decisions, not execution
outcomes.

## 3. Closed Lifecycle

### 3.1 Before claim: current authority or refusal

Gate evaluates the exact action and revalidates time, revocation, evidence, and
program state immediately before claim. A revocation or expiry known at this
point makes the authorization ineligible. Gate must not issue a claim token or
let a stale stage receipt revive the authority.

This is **pre-claim revocation**. Its effect is prospective and preventive: no
new downstream owner claim is minted under the revoked authority.

### 3.2 Claim: one owner, one operation, one bearer capability

A successful claim atomically binds the exact program, CAID, action digest,
stable operation ID, terminal stage-receipt digests, selected downstream owner,
and owner profile digest. It moves controller state from ready to claimed. It
does not prove provider entry or an external effect.

The claim token authorizes submission of the result for only that bound claim.
It must be high entropy, confidential in transit and at rest, omitted from logs,
and disclosed only to the selected worker. Storage should retain only a
domain-separated digest. Exact reuse by the same holder is idempotent; a
different token is refused.

Because it is a bearer capability, token possession is operational authority.
Calling it a worker ID, session label, or receipt does not reduce the need to
protect it as a secret.

### 3.3 Owner result: executed, refused, or indeterminate

The selected downstream owner submits authenticated, operation-bound evidence
for one of these controller results:

- `executed`: the owner verifier accepted evidence that the bound effect
  occurred under its profile;
- `refused`: the owner did not enter or complete the protected effect under the
  bound claim; or
- `indeterminate`: provider entry may have occurred, but the owner cannot yet
  prove either effect or no effect.

These are owner results, not universal statements about physical or legal
reality. `indeterminate` fences the operation and prohibits blind replay.
Authenticated reconciliation of the same operation may later establish
`executed` or `proved_no_effect` without invoking the effect again.

For Action Escrow, `release_indeterminate` is this fenced owner result. It is not
an irreversible terminal state. The Action Escrow owner may reconcile the same
provider operation to `released` or, on authenticated `not_released` evidence,
return to its applicable pre-release state.

### 3.4 After claim: late revocation

Revocation learned after claim or execution is **late revocation**. The system
records the evidence against the exact original operation and action. Its effect
is `future_authority_only`: it may block future claims, inform reliance, or
support a dispute, but it does not relabel the original owner result or erase the
external effect.

Late revocation and authenticated reconciliation answer different questions.
Revocation concerns whether authority remains usable; reconciliation concerns
what happened at the provider. Neither substitutes for the other.

### 3.5 Indeterminate original-effect reconciliation

A relying party may accept dispute or petition evidence while the original
owner result remains `indeterminate`, but it must not authorize an effectful
remedy from that uncertainty alone. The Remedy Program preserves the original
indeterminate observation and appends a separately authenticated reconciliation
bound to the same operation, action, and terminal-evidence digest.

An `executed` reconciliation allows the already-open dispute to proceed. A
`proved_no_effect` reconciliation closes the remedy case without inventing a
return or compensation. Neither result edits the original observation, and a
second contradictory reconciliation is refused.

### 3.6 Dispute and decision

A dispute opens a bounded case against one exact original effect record.
It binds a unique dispute ID, challenger, original operation and action,
evidence, requested remedy units, and opening time. Opening the dispute does not
decide that the challenge is correct and does not authorize a remedy.
If that record is still indeterminate, the dispute is petition intake only
until authenticated original-effect reconciliation establishes `executed`.

A later decision is independently verified and bound to that dispute. The
decision can:

- authorize one exact compensating action within the remaining remedy limit; or
- resolve the dispute with `no_remedy`.

The decision artifact and its authority come from the relying party's pinned
process. Gate verifies and enforces the technical binding; Gate does not act as
the legal or contractual adjudicator.

### 3.7 Compensating action

An authorized remedy must differ from the original operation ID and action
digest. It also binds its own destination, units, unit type, selected downstream
owner, owner profile, and evidence. Partial remedies consume only their verified
executed units; they cannot exceed the original case limit or the dispute's
remaining requested amount.

The remedy then follows the same claim and owner-result discipline as any other
consequential action. An indeterminate remedy remains fenced until authenticated
reconciliation. `proved_no_effect` returns the case to the disputed state without
consuming remedy units. An executed remedy is appended to the remedy history;
the original effect remains unchanged.

Physical return, monetary refund, fee reversal, inventory update, and
entitlement revocation are different material effects. Each must be represented
as its own remedy action, with its own basis/profile, destination, unit,
operation, owner, and result. A multi-leg case is complete only when every
required leg is conclusive; for example, goods received with a refund still
indeterminate is partial, not returned-and-refunded. A shared decision may
authorize several legs only through separately bound leg projections so one
evidence object cannot be replayed as two effects.

## 4. Evidence and Result Vocabulary

| Term | Exact meaning | Must not be treated as |
| --- | --- | --- |
| Authorization decision | Gate's policy result about whether a configured path may advance | Proof that an external effect occurred |
| Claim | Atomic assignment of one bound operation to one downstream effect owner | Execution, identity, recourse, or legal entitlement |
| Comparison verdict | A bounded comparison of named values under a pinned profile | Provider result or execution outcome |
| Owner result / execution outcome | Verified evidence from the selected downstream owner about the bound operation | Universal physical truth, legal finding, or comparison result |
| Receipt assessment | A reviewer or policy engine's assessment of immutable receipt evidence | Mutation of the receipt or external effect |
| Assessment overturned | A later assessment supersedes the earlier assessment | Receipt invalidation, external reversal, or compensating action |
| Dispute | A bounded challenge and its evidence | Decision, remedy authorization, or adjudication |
| Decision | A separately authorized conclusion bound to the dispute | Execution of the remedy |
| Remedy | A fresh compensating action | Rewrite, deletion, or reversal of the original effect record |
| Recourse Reference | Verifiable evidence of a signed, action-bound commitment | Coverage adjudication, solvency, payment, or legal enforcement |

## 5. Persistence and Failure Discipline

Production use would require a durable atomic compare-and-swap store, monotonic
revisions and timestamps, constructor-pinned verifiers, current revocation
checks, stable operation IDs, protected bearer claim tokens, authenticated owner
results, and complete mediation of every protected provider path. Process-local
state is suitable only for explicit tests or demonstrations.

Malformed evidence, unknown fields, verifier exceptions, store unavailability,
stale revisions, wrong operation bindings, reused evidence, wrong claim tokens,
limit overflow, and uncertain provider effects fail closed. Failure to sign,
publish, or assess later evidence never rewrites a previously recorded owner
result.

## 6. Claim Boundary

This profile can make the configured technical lifecycle inspectable and
fail-closed under pinned inputs. It does not establish:

- production deployment, availability, or complete mediation;
- independent implementation, interoperability, or conformance;
- adoption by IETF or any other standards body;
- truth of external facts beyond the accepted owner evidence;
- legal validity, enforceability, liability, coverage, solvency, or payment;
- correctness of an external adjudicator's decision; or
- reversal of an original external effect.

The honest claim is **technically gated under the configured profile**. Every
stronger operational, factual, or legal claim needs separate evidence.
