# CAID Status

Updated: 2026-09-27

## Verified implementation

- A typed action object and strict `caid:1` identifier.
- Registry v5: 62 action types, 53 active and 9 deprecated, a two-suite
  registry with each suite's `digest_octets`, and five integrity-pinned value
  sets (the SIX ISO 4217 List One of 2026-09-17, the IANA DNS RR TYPE, JOSE
  algorithm and JOSE elliptic-curve registries, and ISO 3166-1 alpha-2 as
  carried by the IANA Language Subtag Registry), each with its source,
  retrieval date and licence. Every active type resolves every enum;
  `node caid/registry/check.mjs` computes all 53 under the -04 reference
  validator (`caid/spec/reference.mjs`), and each computes in all three
  ports. Four active types (`payment.refund.2`, `ach.debit.originate.2`,
  `rx.dispense.2`, `prior.auth.approve.2`) use the `code` field type, which
  all three ports implement. Registry v4 is kept byte-identical at
  `registry/history/action-types.v4.json`.
- `caid/spec/`: the ABNF grammar (the draft's Appendix A), the rule data
  (`core.json`), and a deterministic generator for the constants every port
  compiles in. `caid/spec/abnf-check.mjs` checks that the ABNF interpreter
  and the generated JavaScript, Python and Go matchers agree on about half a
  million cases, including astral characters, lone surrogates and strings of
  65,536 characters and more, and that every matcher is linear-time: a static
  analysis plus adversarial inputs of 2^20 characters timed in all three.
- Same-team, dependency-free JavaScript, Python, and Go reference ports.
- 589 of the 591 shared core vectors (corpus version 5) pass in all three
  ports through their JSON text entry points; the other two apply only to a
  cbor-sha256 implementation, and every port here skips them. The vectors
  run with native/byte parity on every
  input that decodes and a native lane for host values: the strict JSON
  text rules and limits, number rounding, deterministic reason order,
  verification details and `definition_mismatch` (with pins of every type),
  definition conformance and `definition_sha256`, host definitions, the
  length limits and the value count (which stops at the nesting limit,
  counts a reference back to an enclosing object or array as one value, and
  applies to host definitions, profiles and sources too), the named code
  formats, `unknown_suite` at parse, and one vector per registry v5 type.
  Six vectors and cases are conditional on cbor-sha256 support, which is
  OPTIONAL: four pin `unknown_suite` where it is not implemented, and two
  (the Appendix C.1 object, the vectors every port here skips) apply only
  where it is. The 96 version 4
  vectors keep their ids, and all 22 version 4 CAIDs reproduce unchanged
  (`caid/conformance/check-v4.mjs`).
- 1,966 grammar boundary cases, and the roughly half-million case list that
  `caid/spec/abnf-check.mjs` writes, passing in all three ports through
  `parseCaid` and `computeCaid`, never through the generated matchers.
- 82 Action-Mapping Profile vectors (version 2) passing with byte-for-byte
  agreement on verdicts and exact reason lists in all three ports, including
  the SILP IR to CAID `CANCEL+EMAIL` profile.
- A differential fuzz of about 88,000 seeded cases in which the JavaScript,
  vendored Verify, Python and Go implementations match the spec oracle, with
  an empty allow list.
- 100 candidate Consequential Action Interoperability vectors covering 25
  revision-pinned mechanisms: native extraction, optional carry, material
  mutation, and missing-field abstention. All pass with identical verdicts
  and refusal reasons in the three same-team ports.
- Closed mapping verdicts: `EQUIVALENT_UNDER_PROFILE`, `NOT_EQUIVALENT`, and
  `INDETERMINATE`. SILP correlation metadata is deliberately non-material;
  ordered entities, action associations, complete constraints, alternatives,
  and action sequence are material, while missing or lossy fields abstain.

Run the complete gate from the repository root:

```sh
npm run caid:conformance
```

These are cross-language ports maintained by the same project. They are not
represented as independent implementations.

External Rust remains a separately pinned third-party historical conformance
record for the earlier clean-room corpus; this repository does not contain or
claim a Rust CAID implementation for the registry-v4 enum behavior.

## Registry v5 compatibility boundary

Registry v5 changes no CAID. It adds type versions, deprecates the nine `.1`
types they supersede (deprecated types still resolve, compute and verify
wherever their fields resolve), and gives `dns.record.delete.1` and
`vendor.onboard.1` their first value-set pins, which changes those two
types' `definition_sha256` and lets them compute. A consumer that pinned the
v4 registry bytes reads `registry/history/action-types.v4.json`.

## Registry v4 compatibility boundary

Valid action objects using currency codes in the pinned ISO 4217 array retain
their existing CAID strings because the definition metadata is not part of the
action object. Issuers and verifiers must nevertheless pin registry v4 and
load the exact enum snapshot. Under v4, bare, unresolved, digest-mismatched,
or out-of-set external enums fail closed, and so do values outside a compact
`inline:` list, which v3-era implementations accepted. Currency codes that v3
accepted but the snapshot omits (for example `BGN` or `HRK`) refuse. External
references that have not yet received immutable snapshot artifacts refuse
whenever their fields are present; because every such field in an active type
was required, those 11 types could not compute at all under v4. Replaying a v3
decision needs the v3 registry and the pre-v4 implementations together (for
example from commit `f46328afc`).

The 25 interoperability mappings are candidates pending author review; they
encode the author's reading of other formats' published specifications, not
validation by those formats' authors. Two have complete CAID-field
extractions under their pinned profiles (one lossless, and one that returns
`INDETERMINATE` because its source action identity commits additional
semantics), eight are partial, and fifteen define no complete native action
artifact. Twenty-four fail closed as `INDETERMINATE`
(`interop/consequential-action-v1/manifest.json`); optional carry-profile
success is not represented as native support or author endorsement.

## Standards status

`draft-schrock-canonical-action-identifier-03` was published as an individual
Internet-Draft on 2026-09-26 through Datatracker submission 169526. It is not
an RFC, an adopted IETF working-group item, or IETF endorsement. The draft
defines the identifier and the profile-bounded mapping algorithm; the IETF
archive is authoritative for the published revision.

Revision -03 specifies the registry-v4 enum behavior described above: pinned,
digest-checked value-set snapshots resolved locally, and fail-closed refusal of
bare, unresolved, mismatched, or out-of-set values. The superseded -02 text,
published 2026-08-06, does not contain it; its snapshot is retained in
`../standards/archive/`.

## Explicit boundaries

CAID identifies and correlates material action content. It does not establish
identity, authority, authorization, safety, execution, or legal reliance.
Each source artifact must first verify under its native specification and
trust anchors. The relying party pins both mapping profiles and type-definition
sources. A mapping result never becomes authorization.

## Deferred

- Deterministic CBOR implementation (`cbor-sha256` is registered and its
  support is OPTIONAL; no port ships it, and its two conformance vectors
  apply only to an implementation that does).
- IANA registry creation, which the -04 draft requests.
- External clean-room implementation of CAID itself.
- Author validation of the 25 candidate adjacent-protocol mappings.
