# CAID Status

Updated: 2026-07-21

## Verified implementation

- A typed action object and strict `caid:1` identifier.
- An immutable 47-type seed registry and two-suite registry.
- Same-team, dependency-free JavaScript, Python, and Go reference ports.
- 48 shared core vectors passing in all three ports.
- 23 Action-Mapping Profile vectors passing with byte-for-byte agreement on
  verdicts and refusal reasons in all three ports, including the SILP IR to
  CAID `CANCEL+EMAIL` profile.
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

## Standards status

`draft-schrock-canonical-action-identifier-01` was published as an individual
Internet-Draft on 2026-07-21. It is not an RFC, an adopted IETF working-group
item, or IETF endorsement. The draft defines the identifier and the
profile-bounded mapping algorithm; the IETF archive is authoritative for the
published revision.

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
- Public binding proposals to adjacent protocols.
