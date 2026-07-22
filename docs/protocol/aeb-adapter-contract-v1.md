# AEB-ADAPTER-v1

`AEB-ADAPTER-v1` is the plug-in boundary for evidence that originates in a
different protocol or trust domain. It does not replace the native protocol
and it does not introduce a universal receipt. A relying party supplies the
trust configuration and decides whether the result is admissible.

## Contract

An adapter is a versioned, deterministic module with two operations:

1. `verifyNative` verifies the artifact in its native format using only the
   trust roots and status input supplied by the relying party.
2. `mapAction` projects the verified artifact through a named, versioned
   mapping profile and returns the resulting CAID.

Adapters must not make network calls or use ambient trust. A profile is valid
only when its digest is pinned in the relying-party configuration. The
presented artifact cannot select a different adapter, profile, root, or
requirement.

The implementation passes adapters detached, recursively frozen copies of the
artifact, status, trust roots, adapter configuration, and mapping profile. This
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

`AEB-REQUIREMENT-v1` makes the authority predicates explicit: `all_of` and
`any_of` role expressions, distinct-human quorum, initiator exclusion, and
mandatory one-time consumption. Composition is delegated to the existing
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

`SATISFIED` requires native verification, relying-party acceptance, a fresh
authenticated status result, a matching CAID, and every role required by the
pinned requirement. A stale, unavailable, or uncheckable status result is
`INDETERMINATE`; it is never treated as approval.

## Multi-leg joins

Several native artifacts may satisfy one requirement when their adapters
produce the same CAID. The requirement is expressed as pinned role predicates
(`all_of` and optional `any_of` groups). A CAID match is a content join, not an
authorization claim.

The package includes a concrete signed-native bridge for protocols whose native
verifier runs at a workload gateway or another trust boundary.
`EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1` binds the native artifact digest,
protocol, audience, evidence role, subject, validity window, mapper, resolver,
mapping profile, CAID, and normalized-action digest under an Ed25519 key pinned
by the relying party. Unsigned headers and presenter-supplied verdicts are
refused. The conformance suite uses the bridge to compose a WIMSE possession
row with a human-authorization row. The bridge consumes the WIMSE verifier's
signed result; it does not redefine WIMSE credential verification.

## Evaluation records

`AEB-EVALUATION-v1` records are signed by an evaluator key pinned by the
relying party. The record includes the evaluator identity, pinned-config
digest, requirement and profile references, artifact references and digests,
per-leg states, CAID, freshness, verdict, and operation/consumption binding.
The record is evidence transport, not a bearer token: a verifier should
re-run the adapters and compare the re-derived body before relying on it.

## Execution boundary

The reference package exposes an atomic consumption-store interface. A local
execution gate:

1. requires a verified, `SATISFIED` evaluation and local authorization;
2. reserves the operation/nonce before invocation;
3. refuses replay after consumption; and
4. freezes an `INDETERMINATE` evaluation for authenticated reconciliation.

An indeterminate invocation outcome remains reserved until reconciliation
proves either `COMMITTED` or `NOT_COMMITTED`. The reference in-memory store
is for tests and examples. The production API requires a durable,
ownership-fenced, permanent-consumption store and is compatible with the
durable store contract in `@emilia-protocol/gate`. Reservation keys are hashed
over relying-party identity, pinned-config digest, CAID, normalized-action
digest, operation, and nonce. Store outages and ownership conflicts fail
closed.

## Reference implementation

The Node verifier exports the contract from
`@emilia-protocol/verify/aeb-adapter-contract` and from the main package
entry. The executable behavior is covered by
`packages/verify/aeb-adapter-contract.test.js` and the shared state vectors in
`conformance/vectors/aeb-adapter.v1.json`.
