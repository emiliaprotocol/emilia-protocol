# CAID Status

Updated: 2026-09-24

## Verified implementation

- A typed action object and strict `caid:1` identifier.
- A 52-type registry v4, two-suite registry, and integrity-pinned 178-code
  `2026-09-17` SIX ISO 4217 snapshot.
- Same-team, dependency-free JavaScript, Python, and Go reference ports.
- 55 shared core vectors passing in all three ports, including valid USD/XAD,
  `NOT-A-CURRENCY`, bare/unresolved external references, hash mismatch, and
  compact inline-enum enforcement.
- 23 Action-Mapping Profile vectors passing with byte-for-byte agreement on
  verdicts and refusal reasons in all three ports, including the SILP IR to
  CAID `CANCEL+EMAIL` profile.
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

## Registry v4 compatibility boundary

Valid action objects using currency codes in the pinned ISO 4217 array retain
their existing CAID strings because the definition metadata is not part of the
action object. Issuers and verifiers must nevertheless pin registry v4 and
load the exact enum snapshot. Under v4, bare, unresolved, digest-mismatched,
or out-of-set external enums fail closed. Other external references that have
not yet received immutable snapshot artifacts remain fail-closed when their
fields are present.

The 25 interoperability mappings are candidates pending author review. Four
have complete extraction fixtures under their pinned profiles, thirteen are
partial, and eight define no complete native action artifact. The latter
twenty-one fail closed as `INDETERMINATE`; optional carry-profile success is
not represented as native support or author endorsement.

## Standards status

`draft-schrock-canonical-action-identifier-02` was published as an individual
Internet-Draft on 2026-08-06. It is not an RFC, an adopted IETF working-group
item, or IETF endorsement. The draft defines the identifier and the
profile-bounded mapping algorithm; the IETF archive is authoritative for the
published revision.

The registry-v4 enum correction is staged for the next Internet-Draft
revision and is not part of the already published `-02` text until the author
submits that revision.

## Explicit boundaries

CAID identifies and correlates material action content. It does not establish
identity, authority, authorization, safety, execution, or legal reliance.
Each source artifact must first verify under its native specification and
trust anchors. The relying party pins both mapping profiles and type-definition
sources. A mapping result never becomes authorization.

## Deferred

- Deterministic CBOR implementation (`cbor-sha256` is defined, not shipped).
- IANA registry creation and policy.
- External clean-room implementation of CAID itself.
- Author validation of the 25 candidate adjacent-protocol mappings.
