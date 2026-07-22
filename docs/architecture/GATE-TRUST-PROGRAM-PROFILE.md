<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Gate Trust Program Profile v1

**Status:** public experimental implementation profile; not a deployment or standardization claim

**Machine discriminator:** `EP-GATE-TRUST-PROGRAM-PROFILE-v1`

**Conformance suite:** `EP-GATE-TRUST-PROGRAM-v1`

**Reference API:** `packages/gate/src/trust-program.ts`

This document is an implementation and operations contract for the public
experimental EMILIA Gate Trust Program build. It is not a standard, an IETF
Internet-Draft, a proposal for IETF adoption, or an assertion of independent
interoperability. The capitalized terms MUST, MUST NOT, REQUIRED, SHOULD, and
MAY describe requirements of this implementation profile only.

## 1. Purpose and boundary

A Trust Program is a relying-party-controlled, fail-closed policy and
enforcement controller for one exact consequential action. It composes
registered evidence verifiers, stage thresholds, signed stage receipts, atomic
state transitions, and one downstream effect-claim owner. Gate decides whether
the configured technical path may advance and fences ownership of one claim; it
does not perform the external effect, adjudicate a dispute, or make the action
legally enforceable. It does not redefine the Handshake, Quorum, AEC,
capability, Receipt Program, or Action Escrow artifact formats.

The profile answers four operational questions:

1. Which evidence seats must be filled?
2. Which stages depend on signed completion of earlier stages?
3. When may Gate issue one fenced claim for the downstream effect owner?
4. Which one downstream kernel owns that effect claim and its result?

The program is closed: unknown program, stage, rule, requirement, or execution
fields are rejected; bounds are fixed by the reference API; every declared
stage must contribute to execution; and evidence cannot create new stages,
weaken thresholds, select trust roots, or choose its downstream effect-claim
owner.

The lifecycle vocabulary in this profile follows
[Lifecycle and Remedy Kernel](./LIFECYCLE-REMEDY-KERNEL.md). In particular, the
original effect record is immutable; a pre-claim revocation can prevent a claim,
whereas a late revocation cannot undo a claimed or executed effect; a dispute is
not a decision; and every remedy is a new compensating action with its own CAID,
action digest, operation ID, authorization, claim, and downstream owner.

## 2. Trust boundaries

- The requester and evidence presenter are untrusted. They may propose an
  action and present artifacts, but they do not choose verifier code, trust
  roots, stage policy, signer context, storage, or consequence mode.
- The relying party pins the program, verifier registry, action/CAID resolver,
  receipt verification key, execution binding verifier, execution outcome
  verifier, reconciliation verifier, and clock policy.
- Each registered verifier retains responsibility for the native artifact's
  cryptographic and semantic validation. The Trust Program consumes only the
  verifier's bounded projection.
- The Trust Program store owns atomic revision state. Production state must be
  shared across replicas and survive process restart.
- Gate owns policy evaluation, evidence admission, stage progression,
  execution-readiness, and atomic claim fencing. It does not own the provider
  effect or the downstream owner's effect assertion.
- Receipt Program or Action Escrow owns the protected effect claim and the
  owner-specific result. A Trust Program grants neither kernel permission to
  bypass its own reserve, execution, outcome, or reconciliation controls.

Complete mediation remains a deployment property. A passing Trust Program has
no authority over a path that can reach the protected system without traversing
the configured Gate and selected effect-claim owner.

## 3. Closed program object

The complete top-level key set is:

| Field                      | Required meaning                                                          |
| -------------------------- | ------------------------------------------------------------------------- |
| `@version`                 | Exactly `EP-GATE-TRUST-PROGRAM-PROFILE-v1`.                               |
| `program_id`               | Stable bounded identifier.                                                |
| `version`                  | Positive safe integer. Material changes require a new version and digest. |
| `root_caid`                | CAID for the exact material action.                                       |
| `action_digest`            | Lowercase `sha256:` digest of the exact action projection.                |
| `valid_from`, `expires_at` | Strict UTC instants with `expires_at > valid_from`.                       |
| `stages`                   | One to 64 closed stage definitions.                                       |
| `execution`                | Closed terminal-stage and downstream effect-claim-owner definition.       |

Canonical JSON safety checks run before semantic validation. The implementation
rejects unsupported values, aliases, cycles, unsafe numeric forms, and other
non-canonical input. The resulting program digest binds the complete program,
including stage order, dependencies, policies, thresholds, validity window,
and downstream effect-claim owner.

### 3.1 Stage definition

Each stage contains exactly `stage_id`, `depends_on`, `rule`, and
`requirements`.

- `depends_on` contains unique known stage IDs and cannot name the stage itself.
- The complete graph must be acyclic.
- Every stage must be an ancestor of a stage named by `execution.depends_on`.
  A disconnected or decorative stage is invalid.
- A rule is exactly `all`, `any`, or `threshold`. A threshold also carries a
  positive `required` value no greater than the number of requirements.
- `distinct_subjects` and `distinct_keys` independently require non-overlapping
  verifier-projected subject and key-fingerprint sets within that stage.

These are orchestration rules over already verified requirement artifacts; they
are not a second implementation of EP-QUORUM. A human M-of-N or ordered approval
trail MUST be verified as one `ep-quorum` requirement by the native Quorum
verifier. It MUST NOT be decomposed into several presenter-supplied `ep-signoff`
seats and relabeled a quorum. Stage-level threshold and separation-of-duties
checks are reserved for heterogeneous relying-party requirements whose native
verifiers provide canonical subject and key projections.

Each requirement contains exactly:

- `requirement_id`;
- `evidence_type`;
- `verifier_profile`;
- `policy_digest`;
- `max_age_sec`, from 1 through 31,536,000; and
- `revocation_required`.

A stage contains one to 64 requirements. A program contains at most 1,024
requirements.

### 3.2 Single downstream effect-claim ownership

The execution object contains exactly `depends_on`, `consequence_mode`,
`capability_template_digest`, and `escrow_profile_digest`.

| `consequence_mode` | `capability_template_digest` | `escrow_profile_digest`   | Downstream owner responsibility |
| ------------------ | ---------------------------- | ------------------------- | ------------------------------- |
| `receipt-program`  | Required `sha256:` digest    | MUST be `null`            | Receipt Program owns the bounded instruction's effect claim and execution evidence. |
| `action-escrow`    | MUST be `null`               | Required `sha256:` digest | Action Escrow owns the release-effect claim and provider reconciliation. |

The mode is required. Both digests non-null, both null, an unknown mode, or a
digest populated for the non-owner is `program_execution_invalid`. This
exclusive choice prevents nested effect-claim ownership: Gate selects and
fences one downstream state machine; Receipt Program and Action Escrow do not
wrap or recursively authorize one another for the same effect. Selection is not
execution, and a successful Gate claim is not an execution outcome.

## 4. Processing model

### 4.1 Construct and start

`createTrustProgramKernel()` validates and clones the program. Production
construction requires a durable store, stage-receipt signing and verification,
and relying-party implementations of action binding, execution binding,
execution-time evidence revalidation, execution outcome, and reconciliation
verification. Process-local state and
omitted production verifiers are permitted only when `allowEphemeralState` is
explicitly true for test or demonstration use.

`start()` accepts a unique instance ID inside the program validity window. The
production action-binding verifier must independently derive and match both the
configured CAID and action digest before state is created. Root stages enter
`collecting`; dependent stages and execution enter `locked`; revision is zero.

### 4.2 Challenge and admit

A seat challenge binds exactly:

- instance ID;
- program digest and version;
- root CAID and action digest;
- stage ID and requirement ID;
- requirement policy digest; and
- sorted predecessor stage-receipt digests.

The canonical digest of that object is the required `binding_digest`. A locked,
completed, unknown, or already-filled seat does not issue a usable challenge.

For admission, the registered verifier must return `valid: true`, the exact
challenge and policy digests, strict issue and expiry instants, subject and key
sets, and a fresh revocation-check instant where required. Gate rejects wrong
CAID, action, stage, seat, policy, predecessor set, stale evidence, expired
evidence, missing or stale revocation status, malformed principal projections,
and replayed evidence IDs before authority advances.

Distinct-person and distinct-key checks operate on the verifier projections.
They are only as reliable as the relying party's enrollment, key registry, and
native verifier. Different labels are not by themselves proof of different
humans.

An accepted artifact records its canonical digest and bounded verifier
projection. The transition increments revision and commits with compare-and-
swap. A stale writer receives `revision_conflict`; it must reload and
re-evaluate rather than overwrite another transition.

### 4.3 Complete a stage

When the rule is satisfied, Gate signs an
`EP-GATE-TRUST-STAGE-RECEIPT-v1` receipt over:

- program, instance, CAID, and action bindings;
- stage and stage-policy digests;
- sorted predecessor receipt digests;
- sorted accepted evidence digests;
- deduplicated subject and key sets; and
- the satisfaction instant.

Signing uses Ed25519 over a domain-separated canonical body. Production must
self-verify the new receipt under the pinned verification key before commit.
Receipt-signing or self-verification failure leaves the stage uncommitted.
Independent verification also binds the exact issuer, tenant, environment,
audience, and key ID. Stage receipts use closed issuer, payload, signature, and
top-level schemas; unsigned extensions are rejected.

A dependent stage unlocks only after every predecessor is `satisfied`; it
captures the predecessors' signed receipt digests in its own challenge and
eventual receipt. A changed receipt body fails digest verification, while a
valid receipt presented against the wrong predecessor expectation fails the
expected-binding check.

### 4.4 Fence one downstream effect claim

Execution becomes `ready` only when all terminal stages named by
`execution.depends_on` are satisfied. Before a claim, Gate rechecks the
freshness, expiry, and required revocation status of all accepted evidence.
Expired authorization cannot be revived by an older stage receipt.

Production durable stores require a stable `operationId` and caller-held claim
token. The compare-and-swap claim binds:

- instance, operation, program, CAID, and action;
- the digest of the pinned issuer, tenant, environment, audience, and key-id
  receipt context;
- sorted terminal stage-receipt digests;
- the exclusive `consequence_mode`; and
- the owner digest, with the non-owner digest null.

The execution-binding verifier must validate that complete object against the
selected downstream kernel. A successful claim moves `ready` to `claimed`; it
does not say that provider entry or any external effect occurred. The claim
token is a bearer capability for this controller transition: possession of the
secret, together with the bound operation, authorizes the holder to submit the
owner result for finalization. It is not an identity credential, receipt,
comparison verdict, or legal entitlement. It must be high entropy, transmitted
only over an authenticated confidential channel, excluded from logs, and
protected like any other bearer secret. The store retains only its digest.
Reusing the exact operation ID and token is idempotent; a different token is
refused.

Every state loaded from storage is revalidated against the pinned program,
stage graph, evidence ledger, signed stage receipts, execution status, and
consequence binding before it can authorize a transition. A canonical but
semantically forged `ready` state is `store_state_invalid`; database integrity
and a matching digest are not treated as authorization by themselves. Claimed,
finalized, and reconciled instants must form a monotonic transition history;
missing terminal timestamps and clock rollback are refused before another
state revision can be committed.

### 4.5 Record the owner result, fence uncertainty, and reconcile

Only the claim-token holder can submit finalization. `executed`, `refused`, and
`indeterminate` are downstream owner results and require a `sha256:` evidence
digest and, in production, successful verification of the supplied owner
evidence against the stored authorization binding. A comparison verdict or
receipt assessment is not an execution outcome and cannot satisfy this check.

`indeterminate` means provider entry may have occurred but success or failure
is not proven. It is a fenced owner result, not a retry grant and not an
irreversible terminal conclusion. A new execution claim returns
`execution_indeterminate`. Only authenticated reconciliation may transition it
to `executed` or `proved_no_effect`; reconciliation does not invoke the effect
again. In the Action Escrow adapter, `release_indeterminate` maps to this fenced
owner result and remains eligible only for Action Escrow's authenticated
reconciliation transitions.

Invalidation or revocation before claim is revision-checked and terminal for
that unclaimed authorization: Gate must not mint a downstream claim after the
authority is no longer current. Revocation learned after claim is late. It may
be recorded for future authority, dispute, and remedy policy, but it does not
rewrite a claimed, indeterminate, or already observed effect as if it had not
occurred. Those states retain their owner result and reconciliation obligations.

## 5. Required operational controls

Production deployment requires all of the following:

1. A durable atomic store implementing create, read, compare-and-swap, and
   revision-checked invalidation without local fallback.
2. Relying-party-pinned native verifiers and trust roots for every declared
   `verifier_profile`.
3. An action resolver that derives the observed CAID and action digest from
   executor-controlled facts.
4. Execution-time revalidation against current revocation and authority state;
   a merely fresh cached timestamp is not enough when the underlying authority
   has since changed.
5. A KMS/HSM or equivalently controlled Ed25519 stage-receipt signer and a
   separately configured verification key.
6. Stable operation IDs, high-entropy bearer claim tokens protected from
   disclosure, and one selected downstream effect-claim owner.
7. Authenticated execution-outcome and reconciliation evidence tied to the same
   operation, action, tenant, environment, and provider boundary.
8. Clock monitoring sufficient to enforce program, evidence, revocation, and
   execution freshness windows.
9. Complete mediation at the protected system or actuator, including separate
   governance of administrator and break-glass paths.

Store unavailability, malformed store responses, verifier exceptions, signer
failure, stale revisions, missing trust configuration, and ambiguous effects
must fail closed. Operators must retain the exact reason and revision for audit
and recovery; they must not convert these failures into a generic success.

## 6. Executable conformance catalog

The authoritative internal catalog is
`conformance/vectors/trust-program.v1.json`. The single reference runner is
`conformance/trust-program-profile.test.js`.

The catalog executes positive DAG progression and exact negative cases for:

- cyclic and disconnected stages;
- partial thresholds and skipped stages;
- wrong CAID, action, policy, and challenge bindings;
- cross-seat replay;
- non-distinct humans and keys;
- stale evidence and missing revocation checks;
- concurrent revision conflict;
- indeterminate no-retry behavior;
- invalidation that preserves an in-flight claim through authenticated
  reconciliation;
- tampered predecessor receipts; and
- valid Receipt Program and Action Escrow ownership, missing ownership, and
  prohibited dual ownership.

Run the suite from the repository root:

```bash
npx vitest run conformance/trust-program-profile.test.js
```

The runner uses the current TypeScript reference API directly, deterministic
time, live generated Ed25519 receipt keys, deterministic verifier projections,
and an ephemeral atomic store. The JSON catalog supplies program mutations,
ordered operations, and expected reasons and revisions. Case IDs do not select
hard-coded outcomes in the runner.

## 7. Claim limitations

A passing `EP-GATE-TRUST-PROGRAM-v1` run demonstrates that this repository's
reference implementation produced the cataloged decisions under the runner's
inputs. It does not establish:

- conformance by an independent implementation or cross-vendor interoperability;
- correctness, security, or availability for cases outside the catalog;
- production durability, key custody, deployment isolation, or complete
  mediation;
- correctness of a real Handshake, Quorum, AEC, revocation service, Receipt
  Program, Action Escrow, provider, or system-of-record integration;
- civil identity, human comprehension, voluntariness, legal authority, or
  absence of coercion;
- truth of external facts or quality of work;
- that an authorized action was wise, safe, lawful, or commercially suitable;
  or
- that a claimed external effect occurred exactly as authorized;
- adjudication of a dispute, reversal of an external effect, or legal
  enforceability of a remedy; or
- deployment, production operation, independent conformance, or adoption as a
  public standard.

Stage receipts prove integrity and attribution under the configured operator
key. They do not make the operator independent. A DAG proves that configured
evidence gates advanced in the declared order; it does not turn weak evidence
into strong evidence. The final assurance is bounded by the native verifiers,
their pinned roots, atomic state, downstream owner enforcement, authenticated
owner-result evidence, and non-bypassability of the protected path. The result
is technically gated under the configured profile; that phrase makes no claim
about legal enforceability.
