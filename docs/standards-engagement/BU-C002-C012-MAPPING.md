<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA mapping for Bu claims C-002 and C-012

Status: informative, source-locked mapping and local implementation evidence.
It does not modify either protocol or claim that one EMILIA artifact satisfies
every claim row.

The reviewed matrix source is
[`draft-bu-agentproto-security-principal-binding-06`](https://datatracker.ietf.org/doc/draft-bu-agentproto-security-principal-binding/),
official archived-text SHA-256
`sha256:4d08f60b22149f4590433a7f37d081700df27b37a457d09ca49cf018da9f5f37`.
It is an active individual Internet-Draft, not an RFC, adopted working-group
item, or IETF endorsement. This mapping follows its Section 18 review-row
fields and its Section 26 negative case, "Refusal consumes single-use
authorization."

The EMILIA source locks are the checked-in posted snapshots recorded by
`standards/STATUS.json`:

- `draft-schrock-ep-authorization-receipts-12`, XML SHA-256
  `66eaa988d974f8535063b35efadc5140331006679b5946bc372d50a16efef52d`;
- `draft-schrock-action-evidence-boundary-05`, XML SHA-256
  `53b09b275fd3868dfbea11340a71e4827c38ad3cba2fdd12595cdcf42eb6c240`;
- `draft-schrock-canonical-action-identifier-02`, XML SHA-256
  `777487b04ac473ad70ff2dd8a0c396657744bb7fd9e92499d4ec0bee67762015`;
  and
- `draft-schrock-ep-quorum-03`, XML SHA-256
  `2c534bead66095bdf1d378100c2d7dd01e157702b3acef945bbfdf1edd0bf557`.

No independent implementation, external interoperability, deployment, or IETF adoption is claimed
by this mapping. The JavaScript implementation and tests cited below are
same-repository source and local-harness evidence.

## C-002: human or organizational authority

### ID and Claim

**C-002.** A relying-party-selected, enrolled approver or distinct approver
quorum produced signed evidence tied to one exact action before execution.
Where an approver identifier denotes a person or organizational role, the
real-world identity and role binding comes from the relying party's directory,
enrollment, and policy. The receipt does not create that relationship.

This row does not assert a standing organizational grant, delegated machine
scope, machine-policy permission, evidence sufficiency for some other role,
local execution authorization, or effect outcome. Those require separate
verified rows or local policy inputs.

### Carrier

`EP-AUTHORIZATION-BUNDLE-v1` carries the Action Object, action hash, signed
Authorization Contexts, signoffs, approver-key proofs, and presentation
evidence. Each context binds the policy, initiator, relying-party audience,
authorization instance, per-signoff nonce, validity window, and optional
native authorization binding to the exact action hash.

The Bundle carries no reservation, terminal consumption, provider invocation,
or effect claim.

### Verifier and Verification rule

The native Authorization Bundle verifier uses relying-party-supplied action,
audience, authorization instance, policy, approver selection, accepted key
classes, approver directory, current status, and any required Class-A,
directory-proof, or presentation-evidence verifier. It checks the closed
schema, action and context commitments, signoff coverage and signatures,
distinct approvers, initiator exclusion, validity windows, audience, current
policy, and required current status.

At an Action Evidence Boundary, each accepted native evidence leg is then
mapped from the executor-observed action through a relying-party-pinned CAID
profile. `EP-AEC-v1` evaluates the complete role requirement. The executor's
local authorization decision remains a later, separate decision.

### Binding

Each signoff covers a `sha256:<lowercase-hex>` digest of one canonical
Authorization Context. The context includes the canonical Action Object hash
and the policy, initiator, audience, authorization instance, nonce, decision,
and expiry fields required by the profile. The effect boundary independently
derives the observed action and its CAID under the pinned mapping profile;
presenter-supplied identifiers are not authoritative.

### Claim grounding

The approval is a signed assertion under an enrolled approver key. The mapping
from the key and approver identifier to a person or organizational role is an
external directory and enrollment result selected by the relying party.
Presentation or platform evidence has only the meaning established by its own
pinned verifier. Signature validity alone does not prove civil identity,
organizational standing, comprehension, legality, or wisdom.

### Signer role and principal relationship

Each approver key signs only in the approver role established by the pinned
directory and policy. For a quorum, each accepted signoff remains attributable
to its own enrolled approver. An agent, authorization server, evaluator, log,
provider, or executor signature cannot substitute for an approver signoff.

### Digest or output representation

Action, context, bundle, profile, configuration, and normalized-action
commitments use the repository's strict canonical JSON and typed
`sha256:<lowercase-hex>` digest rules. Native signatures and public keys use
their profile-defined base64url representation. CAID comparison follows the
exact syntax, suite, mapping profile, resolver version, and output
representation pinned by the relying party. Text that merely looks like the
same digest is not accepted without compatible context and canonical decoding.

### Freshness

The Bundle verifier checks context and approver-key validity windows and the
relying party's current policy. When current status is required, missing,
stale, unavailable, malformed, or revoked status withholds satisfaction. An
offline signature check does not prove current non-revocation. AEB execution
verification separately requires a current authenticated status input for
every leg.

### Accepted result or success behavior

The Bundle verifier may return `SATISFIED` only for the bounded pre-execution
evidence check; its result explicitly carries `authorization_decision: false`.
At AEB the separate stages remain `VERIFIED`, relying-party `ACCEPTED`, CAID
`MATCH`, complete-requirement `SATISFIED`, and local `AUTHORIZED`. No earlier
state implies a later one.

### Relying-party decision

The relying party decides whether the verified and matched C-002 result fills
the `human-authorization` role in its pinned requirement. Gate may authorize an
exact action only after all required roles and local policy succeed. C-002 does
not prescribe a universal allow decision.

### Layer

Application-layer authorization evidence consumed at an executor-side
consequence boundary.

### Failure behavior

Malformed structure, invalid or unpinned signature, approver-selection or
separation failure, policy or audience mismatch, action or authorization-
instance mismatch, missing required presentation evidence, expired evidence,
or authenticated revocation returns `REFUSE` or AEB `UNSATISFIED`. Required
trust, policy, status, or verifier input that is unavailable returns
`INDETERMINATE`. Every such result withholds authorization. A machine-policy
decision or post-execution record cannot fill this row.

### Implementation status and Implemented revision

Implemented for `EP-AUTHORIZATION-BUNDLE-v1`, `AEB-ADAPTER-v1`,
`AEB-EVALUATION-v1`, `EP-AEC-v1`, and the source snapshots named above.

### Specification status and Dependency

Specified by the four individual Internet-Draft snapshots named in the source
lock. The result depends on the relying party's approver directory, enrollment
and key-class policy, audience, current policy, current-status source when
required, mapping profile, resolver, and local authorization rule.

### Evidence reference

- `packages/verify/src/authorization-bundle.ts`
- `packages/verify/authorization-bundle.test.ts`
- `conformance/vectors/authorization-bundle.v1.json`
- `conformance/vectors/quorum.v1.json`
- `packages/verify/src/aeb-adapter-contract.ts`
- `packages/verify/aeb-adapter-contract.test.ts`

## C-012: authorization and attribution boundary

### ID and Claim

**C-012.** EMILIA keeps pre-execution approval evidence, native verification,
material-action matching, evidence sufficiency, local authorization,
reservation, provider entry, effect outcome, and post-execution evidence as
separate claims. A shared action digest, CAID, operation identifier, or evidence
link can correlate those claims but cannot make them interchangeable.

### Carrier

The carriers are intentionally separate:

- `EP-AUTHORIZATION-BUNDLE-v1` carries pre-execution approval evidence and no
  consumption or execution claim.
- `AEB-EVALUATION-v1` carries signed per-leg native-verification and mapping
  results plus the `EP-AEC-v1` requirement verdict.
- the executor-owned durable admission store carries provisional reservation
  and terminal consumption state;
- the Gate execution record carries admission and provider-entry state; and
- authenticated provider or system-of-record evidence, verified under a
  relying-party-selected profile outside the generic AEB record verifier,
  supports effect reconciliation.

### Verifier and Verification rule

Each native artifact first passes its own verifier under pinned trust. AEB
re-derives and verifies the signed evaluation record, exact action, current
status, profile, and requirement. Only a verified execution-time evaluation
with `SATISFIED` evidence and a separate local authorization decision can
reserve the operation and native replay units.

An accepted outcome classification may then reconcile the open reservation:
`COMMITTED` consumes it, `NOT_COMMITTED` releases it, and `INDETERMINATE`
keeps it closed for reconciliation. The generic AEB reconciliation function
does not itself authenticate provider evidence; the caller and Gate boundary
must establish that evidence under the pinned provider or system-of-record
profile before supplying the classification.

### Binding

The pre-execution and post-execution carriers are correlated through the exact
executor-observed action, CAID, normalized-action digest, relying-party and
configuration digest, operation identifier, consumption nonce, executor, and
native replay units. Correlation does not promote attribution into authority or
approval into effect proof.

### Claim grounding

Approver and evaluator records are signed assertions under separately pinned
keys. CAID and normalized-action matches are verifier-derived facts under a
pinned mapping. Reservation and consumption are executor-store facts only
within the store's custody boundary. Effect outcomes require separately
authenticated, action-bound provider or system-of-record evidence; a timeout,
local exception, or unverified callback establishes no outcome.

### Signer role and principal relationship

Approver keys speak for the approval evidence their enrollment supports. The
evaluator key speaks for the evaluation bytes. The executor or provider key
speaks only for its own admission or observed-effect statement. No signature
inherits the role or authority of another signer.

### Digest or output representation

Every join uses the exact typed digest, CAID, profile, and representation named
by its carrier. A CAID match is content correlation, not authorization. A
profile or representation mismatch refuses or becomes `INDETERMINATE`; it is
not repaired by comparing display strings.

### Freshness

Freshness is evaluated per carrier and phase. Current pre-execution status does
not make a later provider observation authentic or current. Historical
verification never becomes execution-authorizing. A signed post-execution
record cannot retroactively prove that approval preceded provider entry.

### Accepted result or success behavior

The accepted output remains a typed sequence: native `VERIFIED`, relying-party
`ACCEPTED`, action `MATCH`, requirement `SATISFIED`, local `AUTHORIZED`, durable
`RESERVED` or `CONSUMED`, and a separately established effect outcome. If the
effect cannot be established, the state remains `INDETERMINATE` and replay is
not reopened.

### Relying-party decision

The relying party selects the required rows and local policy. Gate admits only
after all pre-execution prerequisites succeed and reserves accepted authority
before provider entry. Audit, attribution, log inclusion, or provider outcome
evidence is never a substitute for C-002 pre-execution authority.

### Layer

Cross-phase executor-side consequence admission and evidence correlation.

### Failure behavior

Missing or failed prerequisites withhold the next transition. Refusal before a
reservation leaves the replay unit available. `NOT_COMMITTED` releases an open
reservation and permits a legitimate retry. `COMMITTED` consumes it and replay
returns `consumption_conflict`. If provider entry may have occurred but the
outcome is not established, the reservation stays closed and the result is
`INDETERMINATE` pending authenticated reconciliation.

### Implementation status and Implemented revision

The AEB evaluation, execution-time verification, in-memory reference custody,
durable-store contract, reservation, commit, release, replay refusal, and
reconciliation states are implemented for `AEB-ADAPTER-v1` and
`AEB-EVALUATION-v1`. The in-memory store is test-only. Production prevention
depends on a durable, ownership-fenced, permanent, atomic replay store and
complete mediation at the actual consequence boundary.

### Specification status and Dependency

Specified by `draft-schrock-action-evidence-boundary-05` and the authorization
evidence and CAID snapshots named above. Deployment depends on the resource
owner's non-bypassable Gate placement, durable store, authenticated current
status, and provider or system-of-record evidence verifier. This mapping does
not establish those deployment facts.

### Evidence reference

- `packages/verify/src/aeb-adapter-contract.ts`
- `packages/verify/aeb-adapter-contract.test.ts`
- `packages/verify/src/aeb-acceptance-profile.ts`
- `packages/verify/aeb-acceptance-profile.test.ts`
- `conformance/vectors/aeb-adapter.v1.json`
- `conformance/vectors/oasnt-caid-aeb.v1.json`
- `docs/protocol/aeb-adapter-contract-v1.md`

## Section 26 positive-control disposition

The focused `OASNT-CAID-AEB-VECTORS-v1` local corpus covers Bu Section 26's
"Refusal consumes single-use authorization" case using the current OASNT-02
native verifier and the still-current OASNT-CAID-01 Sections 4.1 and 6.4 source
lock:

1. a near-miss action is refused before AEB reservation and does not consume
   the valid replay unit;
2. a valid reservation reconciled `NOT_COMMITTED` is released and can be
   reserved again; and
3. a valid reservation reconciled `COMMITTED` is consumed, after which replay
   is refused with `consumption_conflict`.

The OASNT-CAID companion remains revision -01 and normatively references core
OASNT-01. The local corpus applies its lifecycle and namespace-separation rules
to tokens verified under the separately source-locked OASNT-02 adapter because
the tested canonical-action bytes and published V5 token remain unchanged. It
does not claim that a revised OASNT-CAID profile for OASNT-02 has been
published, adopted, or independently implemented.
