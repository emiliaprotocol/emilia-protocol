# OAuth Transaction Authorization Composition Profile for AE-CHALLENGE

Status: experimental pre-standard profile text. Both referenced documents are
active individual Internet-Drafts, not IETF working-group documents. This
profile is offered as input to the comparison both author groups have
invited; it can live as a standalone document or as a section of either
draft. Every normative statement below is implemented and tested by the
runnable demonstration in this directory (`demo.mjs`, `demo.test.mjs`; see
the traceability table at the end).

Referenced specifications:

- TXN: draft-rosomakho-oauth-txn-challenge-00
- AE: draft-schrock-ae-challenge-07

## 1. Scope

This profile applies when one protected resource deployment uses both
mechanisms: the native OAuth transaction authorization path of TXN and the
evidence negotiation path of AE. It defines the three things AE Section 1.1
requires such a profile to define (the exact action and audience join, which
challenge is primary for each refusal, and the separation of native grant
state from AE replay state), and it supplies the single-use consumption
state that TXN Section 6.2 requires a protected resource to maintain but
does not define.

Nothing in this profile modifies either referenced specification.

## 2. Routing rule

For each refused operation the protected resource evaluates two conditions
against local policy: whether a transaction-specific native OAuth grant is
required, and whether independently verifiable evidence beyond that grant is
required.

1. Native grant required, no additional evidence required: the refusal
   carries a TXN transaction authorization challenge alone. No AE challenge
   is emitted. Completing AE presentation MUST NOT be offered or accepted as
   a path to authorization (AE Section 1.1).
2. Native grant required and additional evidence required: the TXN challenge
   is primary. The refusal MAY additionally carry an AE challenge scoped
   only to the additional evidence requirements. Satisfying the AE challenge
   MUST NOT satisfy or advance the native grant requirement.
3. No native grant required: the refusal carries an AE challenge alone,
   negotiating whichever independently verifiable evidence forms local
   policy accepts. A TXN challenge MAY still be one of the evidence
   mechanisms the AE challenge names, in which case the resulting
   transaction-bound access token is evaluated as one evidence form under
   Section 3 of this profile.

A refusal carrying both challenges MUST identify the TXN challenge as
primary.

## 3. Exact action and audience join

The protected resource derives one action snapshot for the operation it is
about to perform, before any evidence is inspected. From that same snapshot
it derives, independently:

- the AE challenge action binding (the canonical action digest), and
- the TXN challenge `authorization_details` (TXN Section 4.2.2).

The join between the two mechanisms is this shared derivation, performed by
the protected resource from its own snapshot. The join MUST NOT be
established by identifier equality: the AE challenge identifier and nonce
MUST NOT appear as, or be derived into, the TXN `txn` value, and the `txn`
value MUST NOT appear as the AE challenge identifier or nonce (AE
Section 1.1 and the OAuth Non-Substitution Conformance Case). Any
correlation between a specific AE challenge and a specific `txn` is private
server-side state that the presenter cannot choose or influence.

Audiences remain those of the base specifications: the TXN challenge `aud`
identifies the selected authorization server and the resulting access token
audience follows TXN Section 5.4; the AE challenge audience identifies the
protected resource. Neither audience value is reused for the other
mechanism.

When a transaction-bound access token is evaluated as an evidence form
(routing case 3), the protected resource verifies it natively per TXN
Section 6 (signature, audience, `txn` match against server-side state, and
granted `authorization_details` describing the challenged operation), then
compares the operation described by the granted authorization details
against its own freshly rederived action snapshot. A mismatch is a refusal.

## 4. Refusal primacy and non-substitution

When the native grant requirement is unmet, the operation remains refused
regardless of AE presentation state. The protected resource MUST NOT report
an AE presentation outcome as progress toward, or satisfaction of, the
native grant requirement, and MUST NOT treat a consumed AE nonce as
consuming, reserving, or invalidating any OAuth transaction or access token
(AE Section 1.1).

## 5. State separation and single-use consumption

The protected resource maintains two separate stores:

- AE replay state: consumed AE nonces, per AE's presentation-attempt
  single-use property. This state bounds presentation attempts only; it
  authorizes nothing.
- Native transaction state: the `txn` values it has issued challenges for,
  and the consumption state defined next.

TXN Section 6.2 requires that where single-use semantics apply, the
protected resource "maintain sufficient state to detect replay of the
access token or transaction identifier." For non-idempotent or high-impact
operations this profile defines that state as follows:

1. Before performing the challenged operation, the protected resource
   atomically claims a consumption record keyed by the `txn` value (or the
   token identifier where the deployment tracks tokens). If the record is
   already claimed, the operation is refused without side effects.
2. The claim is durable: it survives process restart, and a retried request
   arriving after a lost response finds the record claimed and does not
   re-execute the effect.
3. If the operation completes, the record is committed with the outcome.
4. If the operation's outcome cannot be determined (dispatch accepted,
   response lost, downstream state unknown), the record is marked
   indeterminate and remains bound to the consumed `txn`. An indeterminate
   record MUST NOT be automatically retried as though the authorization
   remained unused; it is resolved by reconciliation against the same
   record, and the reconciliation outcome is recorded there.

This consumption state belongs to the native transaction store. AE replay
state never substitutes for it and is never consulted for it.

## 6. Graph and loop execution

Workflow continuity is not authority continuity. After task decomposition,
tool selection, retry, or parameter rewriting, each protected resource
rederives the action snapshot for the operation actually about to execute.
A materially changed operation is a new action: it receives its own
challenges under Section 2, its own `authorization_details`, and its own
consumption record. Evidence or tokens bound to the earlier action do not
carry forward across a material change.

## 7. Security considerations

The substitution attacks this profile exists to prevent are: presenting AE
evidence where a native grant is required; reusing one mechanism's
identifier in the other's protocol fields; replaying a consumed transaction
after a lost response; and carrying authorization across a materially
rewritten action. Each is exercised as a negative case in the test suite
below. The base documents' security considerations apply unchanged, in
particular TXN Section 7 (challenge and token bound to the same transaction
identifier, no broadening of granted authorization details) and AE's
fail-closed refusal behavior.

## 8. Traceability to running code

| Profile clause | Test in `demo.test.mjs` |
|---|---|
| §2 routing rule, all three cases | "native OAuth remains primary and AE is allowed only for an additional evidence gap" |
| §3 identifier separation | "AE challenge state never substitutes for the native OAuth transaction" |
| §3 shared-snapshot derivation | "the action digest is rederived from the action about to execute, before any evidence is inspected" |
| §3 evidence-form evaluation of the txn-bound token | "both happy paths satisfy the SAME evaluator, one per evidence form" |
| §4 non-substitution on refusal | "AE-CHALLENGE transport-neutral demo: every case lands on its expected outcome" (cases refusing AE-only presentation where the native grant is required) |
| §5 replay and presenter substitution | "challenge replay and presenter substitution are refused before a second admission" |
| §5.2 lost response does not re-execute | "a lost effect response never re-executes the effect on blind retry" |
| §5.4 outcome states distinct | "the three outcome states stay distinct and all occur" |
| §6 material change is a new action | covered by the rederivation test above plus the tampered-action refusal: "a receipt whose signed action was tampered with after signing is refused" |
| §7 refusals name the failing check | "refusal reasons name the failing check, not a generic error" |
| AE challenge wire shape | "the demo emits an AE-CHALLENGE-07-shaped negotiation object" |
| fixture integrity | "mutation checks: the action fixtures and form identifiers are what the claims rely on" |

Run: `node --test demo.test.mjs` (12 tests).
