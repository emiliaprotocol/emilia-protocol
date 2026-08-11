<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA mapping for Bu claims C-002 and C-012

This is a focused, informative mapping against
[`draft-bu-agentproto-security-principal-binding-05`](https://datatracker.ietf.org/doc/draft-bu-agentproto-security-principal-binding/).
It follows the review-row discipline demonstrated in Section 24.5 of that
draft. It does not modify either protocol, claim IETF adoption, or treat one
EMILIA artifact as satisfying every claim row.

The EMILIA specifications named below are active individual Internet-Drafts.
The implementation evidence is repository-local unless stated otherwise.

## C-002: human or organizational authority

### ID and claim

**C-002.** An enrolled approving principal signed evidence tied to one exact
action before execution. For an approver identifier that denotes a natural
person or an organizational role occupied by a named person, the strength of
that real-world identity or role binding comes from the relying party's
approver directory and enrollment policy, not from the receipt alone.

This row does not assert a general organizational standing grant. A deployment
that requires standing or delegated organizational authority must verify that
authority as a separate evidence role.

### Carrier

`EP-AUTHORIZATION-BUNDLE-v1`, defined by
`draft-schrock-ep-authorization-receipts-11`, carries the Action Object, signed
Authorization Contexts, signoffs, approver-key proofs, and presentation
evidence. Each Authorization Context carries the action hash, policy reference,
initiator, relying-party audience, authorization instance, per-signoff nonce,
and validity window.

The bundle deliberately carries no reservation, terminal consumption, or
execution claim.

### Signer role and principal relationship

An approver-held key signs each Authorization Context. The key is enrolled
under an approver identifier selected through the relying party's directory
and policy. The directory authority, not the signature format, asserts the
mapping from that identifier to a natural person or organizational role.

For a quorum, each required signoff remains attributable to its own enrolled
approver. Distinctness, initiator exclusion, and executor exclusion are
separate relying-party rules. An agent, authorization server, evaluator, log,
or executor signature does not become an approver signature merely because it
is valid.

### Verifier and rule

The native Authorization Bundle verifier checks the closed schema, canonical
action hash, signed contexts, approver-key proofs, policy and audience
bindings, validity window, signoff distinctness, and any required presentation
evidence under relying-party-selected trust inputs.

At an Action Evidence Boundary, the relying party then:

1. accepts the native verifier and its trust configuration for the
   `human-authorization` role;
2. rederives the observed material action at the executor and establishes a
   CAID match under a pinned mapping profile;
3. evaluates the complete AEC requirement without allowing another evidence
   role to substitute for C-002; and
4. makes a separate local authorization decision.

### Binding, representation, and freshness

The approver signature covers an Authorization Context bound to the canonical
Action Object hash, policy, initiator, audience, authorization instance,
signoff nonce, and expiry. The effect boundary independently constructs the
observed action and rederives its CAID under
`draft-schrock-canonical-action-identifier-02`; presenter-supplied action
identifiers are not authoritative.

The bundle verifier checks the signed validity window. Current revocation and
status are separate relying-party inputs. Offline verification does not prove
current non-revocation. At execution time, missing, stale, unauthenticated, or
unavailable required status withholds authorization and is not rewritten as a
successful C-002 result.

### Accepted result

The constrained accepted result is that an enrolled approver evidence leg is
native-verified, accepted under pinned relying-party trust inputs, and matched
to the exact observed action for the `human-authorization` role.

It does not by itself establish the real-world identity proofing strength,
organizational standing authority, satisfaction of every required evidence
role, the relying party's local authorization decision, reservation,
consumption, invocation, or physical effect.

### Failure behavior

Malformed structure, invalid signature, unpinned or out-of-window key, policy
or audience mismatch, duplicate or excluded approver, missing required
presentation evidence, action mismatch, expiry, or authenticated revocation
fails the C-002 row. An unavailable required current-status source produces an
indeterminate result that withholds authorization. A workload credential,
machine-policy decision, authorization-server assertion, or post-execution
record cannot silently fill this row.

### Status and evidence

- **Specification status:** specified externally by
  `draft-schrock-ep-authorization-receipts-11`,
  `draft-schrock-ep-quorum-03`,
  `draft-schrock-canonical-action-identifier-02`, and
  `draft-schrock-action-evidence-boundary-03`.
- **Implementation status:** implemented in the repository's Authorization
  Bundle verifier and AEB adapter contract.
- **Evidence type:** source-level and local-harness. No independent
  implementation or interoperability result is claimed by this mapping.
- **Evidence references:**
  `packages/verify/src/authorization-bundle.ts`,
  `packages/verify/authorization-bundle.test.ts`,
  `conformance/vectors/authorization-bundle.v1.json`,
  `conformance/vectors/quorum.v1.json`, and
  `packages/verify/aeb-adapter-contract.test.ts`.

## C-012: authorization and attribution boundary

### ID and claim

**C-012.** EMILIA keeps pre-execution approval evidence, native verification,
material-action matching, evidence sufficiency, local authorization,
reservation or consumption, invocation, effect outcome, and post-execution
audit evidence as separate claims. A shared action digest, CAID, operation
identifier, or evidence link correlates those claims but does not collapse one
into another.

### Carrier

The principal carriers are deliberately separate:

- `EP-AUTHORIZATION-BUNDLE-v1` carries pre-execution approver evidence and no
  consumption or execution claim.
- `AEB-EVALUATION-v1` carries the evaluator's per-leg native-verification and
  action-mapping results, AEC satisfaction result, and separate local decision.
- The executor's durable admission store carries provisional reservation and
  terminal consumption state.
- `EP-AUTHORIZATION-RECEIPT-v1` carries signed contexts, a terminal consumption
  record, and log-inclusion material. That record remains evidence and is not
  proof that a physical effect occurred.
- Authenticated provider or system-of-record evidence carries the effect
  outcome used for AEB reconciliation.

### Signer role and principal relationship

Approver keys sign Authorization Contexts. A pinned evaluator key signs an AEB
evaluation record. A transparency-log key signs a checkpoint. An authenticated
provider or system-of-record identity supplies an accepted outcome observation.
Each signer speaks only for its own artifact and claim. No one of these
signatures inherits the authority or semantics of another.

### Verifier and rule

Each artifact first passes its native verifier under relying-party-selected
trust inputs. The Action Evidence Boundary then keeps `VERIFIED`, `MATCH`,
`SATISFIED`, and local `AUTHORIZED` distinct. Only after local authorization
may the executor atomically reserve the operation and native replay units.

After invocation begins, the executor classifies the effect as `EXECUTED`,
`FAILED`, or `INDETERMINATE` using authenticated, action-matched provider or
system-of-record evidence. A timeout or local exception is not evidence that
the effect failed.

### Binding, representation, and freshness

Pre-execution and post-execution carriers are joined through the exact observed
action, its CAID and normalized-action digest, the relying-party audience,
operation identifier, and consumption identity. The mapping profiles, policy
epoch, trust roots, status inputs, and verifier revisions are pinned by the
relying party.

Freshness is evaluated per artifact and phase. A current pre-execution decision
does not make a later provider observation authentic or current. A signed
post-execution record does not retroactively prove that approval preceded the
effect.

### Accepted result

The result remains a typed set of bounded claims:

- accepted approver evidence for the exact action;
- a complete evidence requirement that is `SATISFIED` or not;
- a separate local `AUTHORIZED` or refused decision;
- durable `RESERVED`, `CONSUMED`, or reconciliation-required lifecycle state;
  and
- an effect outcome established by accepted provider evidence, or
  `INDETERMINATE` when that evidence cannot establish the outcome.

No audit, log-inclusion, attribution, or outcome record is accepted as a
substitute for pre-execution C-002 authority.

### Failure behavior

Missing or failed prerequisites withhold the later transition. A refusal before
provider commitment must leave a provisional reservation reusable by releasing
both the operation key and its native replay keys. A successful committed path
consumes the reliance unit, and a replay is refused. If invocation may have
reached the provider but the outcome is unknown, the reservation remains closed
and the result is `INDETERMINATE` pending authenticated reconciliation.

### Status and evidence

- **Specification status:** specified externally by
  `draft-schrock-ep-authorization-receipts-11` and
  `draft-schrock-action-evidence-boundary-03`.
- **Implementation status:** implemented by the AEB evaluation, admission, and
  reconciliation contract. The reference in-memory store is for tests; the
  production API requires durable, ownership-fenced, permanent, atomic replay
  custody.
- **Evidence type:** source-level and local-harness. This mapping claims no live
  deployment or external interoperability evidence.
- **Evidence references:**
  `packages/verify/src/aeb-adapter-contract.ts`,
  `packages/verify/aeb-adapter-contract.test.ts`,
  `conformance/vectors/aeb-adapter.v1.json`, and
  `docs/protocol/aeb-adapter-contract-v1.md`.

## Section 26 negative-case disposition

Bu Section 26's "Refusal consumes single-use authorization" negative is
covered by the focused regression named:

`AEB releases a provisional reservation on pre-commit refusal and consumes only after commitment`

The regression establishes both controls:

1. `NOT_COMMITTED` before provider commitment releases the provisional
   reservation and permits the same valid authorization to be reserved again.
2. `COMMITTED` consumes the reservation, after which replay is refused with
   `consumption_conflict`.

Ordinary exact-action, subject, policy, evidence, and local-authorization
refusals are evaluated before the reservation transition, so those paths have
no provisional state to release.
