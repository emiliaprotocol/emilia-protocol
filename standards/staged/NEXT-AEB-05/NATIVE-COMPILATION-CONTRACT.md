<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-05 candidate section: native compilation contract

STATUS: contribution text incorporated into the authorized AEB-05 submission
packet. AEB-04 remains the current published revision until the Datatracker
confirms the replacement. This text does not create a new wire format, token,
receipt, or registry.

Implementation and conformance material:

- `docs/protocol/aeb-adapter-contract-v1.md`
- `packages/verify/src/aeb-adapter-contract.ts`
- `packages/verify/aeb-adapter-contract.test.ts`
- `packages/verify/src/aeb-native-compiler.ts`
- `packages/verify/aeb-native-compiler.test.ts`
- `examples/aeb-native-compiler-v1/`
- `conformance/composition/authzen-coaz-mcp-aeb-v0.1/`
- `conformance/composition/oauth-txn-challenge-aeb-v0.1/`
- `conformance/vectors/aeb-adapter.v1.json`
- `packages/verify/src/aeb-consequence-conformance.ts`
- `conformance/vectors/aeb-consequence-conformance.v1.json`

---

## Proposed section: Native Compilation Contract

### X.1. Purpose

An AEB adapter compiles the result of a native verifier into the inputs needed
by the AEB processing model. The native artifact, verifier, trust model, and
result remain authoritative for their own semantics. Compilation MUST NOT
convert a native result into an EMILIA credential or allow an AEB result to
overwrite the native result.

The compilation target is the ordered AEB decision and lifecycle vocabulary:
native verification, exact-action matching, evidence-requirement satisfaction,
local authorization, atomic reliance reservation or consumption, provider
entry, outcome classification, and authenticated reconciliation. A successful
compile establishes only that the native result can be evaluated at those
interfaces. It does not establish that the action is authorized, executed,
safe, lawful, or true.

### X.2. Pinned adapter inputs

Before compilation, the relying party MUST pin all of the following:

- the native protocol, document revision, media type, schema version, and
  verifier revision;
- the verifier implementation identifier and implementation digest;
- native trust anchors, issuer and audience policy, clock, freshness rules,
  and required status sources;
- the exact source descriptor and target CAID action type;
- the mapping profile identifier, revision, and digest;
- the accepted evidence role or roles;
- the replay-unit derivation profile and replay scope; and
- every native field whose omission or change can affect the protected
  consequence, evidence role, freshness, replay unit, or local policy.

The presented artifact MAY select among already pinned native variants only
where the native protocol defines that selection and the relying party has
enabled it. Presenter-controlled data MUST NOT add a trust root, verifier,
mapping, evidence role, material-field rule, or replay scope.

A verifier implementation identifier and digest are relying-party-selected
configuration metadata. They do not prove that a measured runtime loaded or
executed those bytes. A compile result MUST keep runtime measurement
unestablished unless a separate accepted native attestation proves it.

### X.3. Deterministic operations

An adapter exposes two logically separate operations:

1. `verifyNative` verifies the native artifact under the pinned native rules
   and returns the integrity-protected native result.
2. `mapAction` maps only a VERIFIED native result to the relying party's exact
   expected action under the pinned mapping profile.

Both operations MUST be deterministic for the supplied bytes and pins. They
MUST NOT perform a network request, consult ambient credentials or trust
stores, read mutable global state, or accept a caller-supplied verification
verdict. Required current status and time are explicit relying-party inputs.

The boundary MUST supply detached, recursively immutable copies of the native
artifact, expected action, trust inputs, status inputs, adapter configuration,
and mapping profile. An adapter MUST NOT be able to change a pinned input
between native verification and action mapping.

### X.4. Closed compile result

For each artifact, the compiler MUST return a closed result containing:

- native protocol and exact revision;
- native artifact digest and native verification result;
- adapter identifier, revision, and configuration digest, plus the pinned
  verifier implementation identifier, revision, and digest;
- mapping profile identifier, revision, and digest, plus mapper and resolver
  identifiers and the resolver implementation digest;
- source schema or media type and target action type;
- the exact relying-party-supplied expected material action value, digest, and
  input provenance;
- CAID and normalized-action digest, or a named reason they were not produced;
- accepted evidence role and subject, plus the status input and derived
  freshness result under pinned adapter rules;
- stable native replay unit and replay scope;
- whether verifier runtime measurement is established;
- a complete semantic-loss report as defined below; and
- every compiler state that remains unsupported or indeterminate.

The compile result is typed verifier output. It is not a bearer token, permit,
receipt, or proof of execution. A deployment MAY serialize it for diagnostics
or evidence transport, but that serialization MUST NOT become reusable
authority.

A native profile MAY expose actor, acting-for principal, target, declared
purpose, audience, constraints, validity, or native nonclaims only when its
native verifier and pinned mapping establish those values. The generic
compiler MUST NOT infer them from a subject identifier, policy decision,
action label, natural-language field, or trace metadata merely to fill a
common shape.

A caller-supplied local-policy decision MAY be reported as an explicit input,
but it MUST NOT establish local authorization. Authorization, reservation or
consumption, provider entry, outcome, and reconciliation remain unestablished
until the component that owns each transition evaluates and records it.

### X.5. Semantic-loss report

The adapter MUST enumerate every source field that the native verifier exposes
but the selected mapping does not carry into the target action or accepted
evidence role. Each omission MUST be classified as `material`,
`non_material`, or `unknown` under relying-party-pinned rules, with a stable
field path and basis.

An omitted `material` or `unknown` field makes exact-action matching
INDETERMINATE. The compiler MUST NOT report `EQUIVALENT_UNDER_PROFILE`, MATCH,
SATISFIED, or AUTHORIZED for that leg. Renaming, moving, defaulting,
unit-converting, rounding, truncating, or combining a material field counts as
a transformation and requires a pinned deterministic rule. Natural-language
similarity, an agent assertion, or a shared trace identifier is not such a
rule.

The compiler MAY retain a native mapper's raw relation, CAID, and normalized
action digest for diagnostics, but MUST label them as raw native output. They
MUST NOT appear as the compiler-effective relation after material or unknown
loss. The effective CAID and normalized-action digest are absent in that case.

If two compiled legs produce one CAID but different normalized-action digests,
the boundary MUST refuse the join. CAID remains a typed content identifier, not
an authorization claim and not a general declaration that two source formats
have identical semantics.

### X.6. Stable native replay unit

Every accepted authorization-bearing native result MUST expose a stable native
replay unit derived from the verified native authority. The replay unit MUST
NOT include an AEB wrapper digest, AEB operation identifier, consumption nonce,
request retry identifier, or other value whose change would make the same
native authority spendable again.

The evaluator MUST probe the adapter with a second deterministic wrapper
reference. If the replay unit changes while the verified native authority does
not, the result is INDETERMINATE. If two distinct verified native artifacts
from one adapter collapse onto one replay unit without the native profile
defining that equivalence, the result is INDETERMINATE. Reservation or
consumption remains an AEB state transition; a replay-unit value alone does not
prove that transition occurred.

### X.7. Path and provider ownership

A deployment MUST state whether the AEB boundary controls the credential or
other capability that reaches the effecting provider, which provider-entry
paths it mediates, and every direct, administrator, break-glass,
alternate-protocol, queued, or system-of-record path that bypasses it. An
observe-only adapter or an adapter placed beside a write path MUST NOT be
described as consequence admission or complete mediation.

The compile result MAY record provider-attempt and reconciliation bindings only
after the corresponding AEB transitions occur. An AuthZEN allow, OAuth token,
message signature, SCITT receipt, Capsule, audit record, or native permit MUST
NOT be relabeled as proof that provider entry, commitment, or an external
effect occurred.

### X.8. Conformance

A native compilation profile MUST publish:

- exact source locks for every normative native input;
- at least one positive vector with the original native bytes;
- a condition-removed control for every negative vector;
- separate native, mapping, AEC, local-policy, reservation, provider-outcome,
  and reconciliation results;
- hostile vectors for material-field omission and substitution, mapping-pin
  change, stale or unavailable status, wrapper replay, alternate-path bypass,
  refusal-time consumption, concurrent admission, timeout after provider
  entry, blind retry, and reconciliation binding mismatch; and
- an explicit statement of any native semantics that could not be compiled
  without invention.

A generic AEB compiler conformance claim requires at least two materially
unrelated native profiles to reach the same AEB lifecycle without changing
their native wire formats or result semantics. A same-team runner is reference
evidence, not an independent implementation. Matching a finite vector set does
not establish complete mediation, production deployment, or provider truth.

---

## Proposed -05 change note

- Defines a deterministic, loss-aware native compilation contract for AEB
  adapters.
- Requires explicit source and implementation pins, a closed compile result,
  a complete semantic-loss report, and stable native replay units.
- Adds conformance requirements across at least two unrelated native profiles
  while preserving native result ownership and AEB's non-collapsing lifecycle.
- Creates no new wire format, token, receipt, registry, or assertion that a
  compiled artifact was authorized or executed.

## Candidate status and review boundary

This section is backed by same-team implementation and vectors for two
materially unrelated code paths: an EMILIA-signed local PEP observation
derived from AuthZEN/COAZ-MCP, and the native OAuth Transaction Authorization
Challenge artifact pair. Both pass locally, which establishes two-path
feasibility. The AuthZEN-derived envelope is not an AuthZEN artifact, so it does
not count toward the two-external-native-profile gate. A third passing path
directly verifies WPT-02 and Transaction Tokens -11 under a strict,
request-only application profile. It is the second external-native candidate,
but does not close the gate without native-owner review, a full paired-control
audit, and an explicit judgment that the two OAuth-adjacent candidates are
materially unrelated enough for the generic claim. The OAuth profile now sends
two in-flight admissions through one in-process reference store and gets one
reservation, but that bounded result does not establish distributed-store
concurrency safety or close the complete conformance gate. These results do not
establish native interoperability, external review, independent reproduction,
working-group adoption, or deployment. Filing was authorized on 2026-08-31 so
the proposed contract can receive public review. Each native profile owner
should be asked only whether the mapping preserves that profile's semantics
and nonclaims. They should not be asked to endorse EMILIA or AEB.
