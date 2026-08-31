# AEB-ADAPTER-v1

`AEB-ADAPTER-v1` is the plug-in boundary for evidence that originates in a
different protocol or trust domain. It does not replace the native protocol
and it does not introduce a universal receipt. A relying party supplies the
trust configuration and decides whether the result is admissible.

## Developer entry point

`compileAebNativeEvidence` is the neutral SDK surface over this contract. It
accepts unchanged native artifacts, relying-party pins, pure native verifiers,
mapping profiles, native protocol and verifier descriptors, a relying-party
expected action, an AEC requirement, and a local-policy input. It returns a
closed, deterministic report with native verification, acceptance,
exact-action matching, evidence satisfaction, declared semantic loss, and
replay identity kept separate. The expected action and policy decision are
marked `RELYING_PARTY_INPUT`; the compiler does not claim independent
provenance, authentication, or execution for either input.

The compiler reports an `ALLOW`, `DENY`, or `INDETERMINATE` policy input, then
stops. Local authorization is `NOT_EVALUATED`. Reservation, consumption,
provider entry, outcome, observed effect, retry, and reconciliation also remain
`NOT_EVALUATED` or `NOT_ESTABLISHED` until Gate performs the corresponding
work. A pinned verifier implementation digest is configuration metadata, not
proof that a measured runtime executed it.

Import the compiler from `@emilia-protocol/verify/aeb-native-compiler` or the
main package entry. The runnable
[`ACME-DELEGATION example`](../../examples/aeb-native-compiler-v1/README.md)
shows a native Ed25519 artifact compiling without changing its wire bytes.

## Contract

An adapter is a versioned, deterministic module with two operations:

1. `verifyNative` verifies the artifact in its native format using only the
   trust roots, expected action, and status input supplied by the relying party.
2. `mapAction` projects the verified artifact through a named, versioned
   mapping profile and returns the resulting CAID.

Adapters must not make network calls or use ambient trust. A profile is valid
only when its digest is pinned in the relying-party configuration. The
presented artifact cannot select a different adapter, profile, root, or
requirement. This is an adapter contract; the compiler does not sandbox code
supplied by its caller.

The implementation passes adapters detached, recursively frozen copies of the
artifact, expected action, status, trust roots, adapter configuration, and mapping profile. This
prevents an adapter or hostile input object from mutating the relying party's
pinned configuration between native verification and action mapping.

## Mapping equivalence

Every CAID mapping pin names an accepted mapper and a resolver by identifier,
version, and implementation digest. It also records all omitted material and
non-material source fields. A profile that omits a material field cannot claim
`EQUIVALENT_UNDER_PROFILE`; evaluation becomes `INDETERMINATE`. Two legs that
return one CAID but different normalized-action digests are refused. CAID is a
join key, never an unqualified claim that unlike source formats have identical
semantics.

## One registry and one requirement

`EP-EVIDENCE-REGISTRY-v1` is the single typed registry for mapping profiles,
evidence roles, and receipt extensions. Entry kind, definition digest, registry
epoch, and complete registry digest are pinned. A mapping entry cannot be
substituted for an evidence role even if the outer registry digest is
recomputed.

`AEB-REQUIREMENT-v1` makes the authority predicates explicit. `all_of` and
`any_of` are role expressions. Its typed `terms` array carries
`distinct-human-quorum`, `initiator-exclusion`, `executor-exclusion`,
`evidence-binding`, and the mandatory `one-time-consumption` execution
predicate. `evidence-binding` joins a signature-verified digest claim from one
role to the exact `evidence_digest` of a separately verified target role and
can require the two legs to identify the same subject. A linked digest never
satisfies the target role by itself. A requirement with an unknown
term, duplicate quorum role, duplicate exclusion term of either kind, or anything other than
exactly one one-time-consumption term is invalid. Composition is delegated to
the existing
`EP-AEC-v1` verifier with a relying-party-pinned requirement over the exact
CAID and normalized action digest. AEB does not implement a second evidence
chain.

## Separate decisions

The verifier keeps the following states distinct:

- `VERIFIED` / `FAILED`: native artifact verification.
- `ACCEPTED` / `REJECTED` / `INDETERMINATE`: relying-party acceptance under
  the pinned adapter and trust configuration.
- `SATISFIED` / `UNSATISFIED` / `INDETERMINATE`: the complete evidence
  requirement for one CAID.
- `AUTHORIZED`: a local execution decision after evidence is satisfied.

`SATISFIED` requires native verification, relying-party acceptance, a status
input whose derived freshness passes the pinned adapter rules, a matching
CAID, and every role required by the pinned requirement. `AebStatusInput` is
caller-supplied data that is shape-checked and digest-bound; this contract does
not authenticate its provenance. A stale, unavailable, or uncheckable status
input is `INDETERMINATE`; it is never treated as approval.

The native compiler stops at evidence satisfaction. Its policy input is not
the `AUTHORIZED` state described above, and its local-authorization axis stays
`NOT_EVALUATED` even when the policy input says `ALLOW`.

The evaluation record binds the initiator and, when the requirement uses
`executor-exclusion`, the server-selected executor. A subject satisfying an
excluded approval role cannot also be the initiator or executor. This is an
identifier-separation invariant; the relying party remains responsible for
anchoring those identifiers to real people or workloads.

## Multi-leg joins

Several native artifacts may satisfy one requirement when their adapters
produce the same CAID. The requirement is expressed as pinned role predicates
(`all_of` and optional `any_of` groups). A CAID match is a content join, not an
authorization claim.

The Authorization Server confirmation profile uses `evidence-binding` to join
an enterprise AS grant to the exact human-authorization artifact it confirms.
The human verifier and AS verifier remain independent, and Gate still owns the
final local admission decision. See
[`Authorization Server Confirmation Profile v1`](authorization-server-confirmation-profile-v1.md).

The package includes a concrete signed-native bridge for protocols whose native
verifier runs at a workload gateway or another trust boundary.
`EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1` binds the native artifact digest,
protocol, audience, evidence role, subject, validity window, mapper, resolver,
mapping profile, CAID, and normalized-action digest under an Ed25519 key pinned
by the relying party. Unsigned headers and presenter-supplied verdicts are
refused. The conformance suite uses the bridge to compose a WIMSE possession
row with a human-authorization row. The bridge consumes the WIMSE verifier's
signed result; it does not redefine WIMSE credential verification.

Every accepted native result also carries a stable `replay_unit` derived from
the native authorization itself. It does not include the AEB operation ID or
consumption nonce. Changing the AEB wrapper therefore cannot make one native
approval spendable again. The evaluator probes every adapter with a second,
deterministic wrapper reference and makes the leg `INDETERMINATE` if the replay
unit changes. It also refuses an evaluation when two distinct verified native
artifact digests from one adapter collapse onto the same replay unit. These
checks turn wrapper parity and intra-evaluation collision detection into runtime
invariants rather than adapter-specific documentation claims.

## Evaluation records

`AEB-EVALUATION-v1` records are signed by an evaluator key pinned by the
relying party. The record includes the evaluator identity, pinned-config
digest, requirement and profile references, artifact references and digests,
per-leg states, CAID, freshness, verdict, and operation/consumption binding.
The record is evidence transport, not a bearer token: a verifier should
re-run the adapters and compare the re-derived body before relying on it.
Both the pinned evaluator key and the signing key are required to be Ed25519;
an RSA or P-256 key labeled as `Ed25519` is refused before a record can become
execution-authorizing.

Historical verification re-derives the status snapshot signed into the
evaluation and always returns `execution_authorizing: false`. It is the default
when live execution inputs are absent. Execution-time verification is a
separate explicit mode: it requires the exact normalized action, verifier
clock, and a fresh status input evaluated under the pinned adapter rules for
every leg. A missing, stale, consumed, revoked, or unavailable current-status
input fails closed. `EP-STATUS-v1` is the separate portable signed profile for
deployments that need an offline-verifiable status artifact; `AebStatusInput`
alone does not establish that provenance.

## Execution boundary

The reference package exposes an atomic consumption-store interface. A local
execution gate:

1. requires a verified, `SATISFIED` evaluation and local authorization;
2. atomically reserves the operation/nonce and every native replay unit before invocation;
3. refuses same-operation and rewrapped-native-evidence replay after consumption; and
4. freezes an `INDETERMINATE` evaluation for authenticated reconciliation.

An indeterminate invocation outcome remains reserved until reconciliation
proves either `COMMITTED` or `NOT_COMMITTED`. The reference in-memory store
is for tests and examples. The production API requires a durable,
ownership-fenced, permanent-consumption store and is compatible with the
durable store contract in `@emilia-protocol/gate`. Reservation keys are hashed
over relying-party identity, pinned-config digest, CAID, normalized-action
digest, operation, and nonce. Native replay keys are separately namespaced by
the relying party. A production store must explicitly declare durable custody,
ownership fencing, permanent consumption, and atomic replay fencing. Store
outages, partial multi-key reservations, and ownership conflicts fail closed.

## Reference implementation

The Node verifier exports the contract from
`@emilia-protocol/verify/aeb-adapter-contract` and from the main package
entry. The executable behavior is covered by
`packages/verify/aeb-adapter-contract.test.js` and the shared state vectors in
`conformance/vectors/aeb-adapter.v1.json`.

The public, format-neutral consequence-boundary self-assessment is
[`AEB-1 Consequence Admission Conformance`](../conformance/AEB-1-CONSEQUENCE-ADMISSION.md).
It adds hostile cross-state and reconciliation vectors without defining a new
evidence format or turning a self-reported result into certification.
