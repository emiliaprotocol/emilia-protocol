# CAID Status

Updated: 2026-09-26

## Verified implementation

- A typed action object and strict `caid:1` identifier.
- A 52-type registry v4, two-suite registry, and integrity-pinned 178-code
  `2026-09-17` SIX ISO 4217 snapshot. 41 active types compute under v4. The
  other 11 (`payment.refund.1`, `ach.debit.originate.1`, `key.create.1`, `key.rotate.1`, `dns.record.delete.1`, `firewall.rule.open.1`, `pii.export.1`, `rx.dispense.1`, `prior.auth.approve.1`, `phi.disclose.1`, and `vendor.onboard.1`) cannot produce or verify a CAID until their external
  code sets receive pinned snapshots; the registry lists the blocking fields
  in `unresolved_external_enums`.
- Same-team, dependency-free JavaScript, Python, and Go reference ports.
- 88 shared core vectors (corpus version 3) passing in all three ports,
  including valid USD/XAD, `NOT-A-CURRENCY`, bare/unresolved external
  references, hash mismatch, compact inline-enum enforcement and trimming,
  null enum members, own-member field presence, unpaired-surrogate
  refusals, whole-string grammar refusals (a value followed by a line feed
  never matches a grammar), and value-based integer fields (`12.0` and
  `1.2e1` are the integer 12; an integer beyond 2^53-1 refuses once as
  `unsupported_number`). The Go port adds unit tests for its strict JSON
  decoder.
- 25 Action-Mapping Profile vectors passing with byte-for-byte agreement on
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
or out-of-set external enums fail closed, and so do values outside a compact
`inline:` list, which v3-era implementations accepted. Currency codes that v3
accepted but the snapshot omits (for example `BGN` or `HRK`) refuse. External
references that have not yet received immutable snapshot artifacts refuse
whenever their fields are present; because every such field in an active type
is required, those 11 types cannot compute at all under v4. Replaying a v3
decision needs the v3 registry and the pre-v4 implementations together (for
example from commit `f46328afc`).

The 25 interoperability mappings are candidates pending author review. Four
have complete extraction fixtures under their pinned profiles, thirteen are
partial, and eight define no complete native action artifact. The latter
twenty-one fail closed as `INDETERMINATE`; optional carry-profile success is
not represented as native support or author endorsement.

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

- Deterministic CBOR implementation (`cbor-sha256` is defined, not shipped).
- IANA registry creation and policy.
- External clean-room implementation of CAID itself.
- Author validation of the 25 candidate adjacent-protocol mappings.
