# CAID — Canonical Action Identifiers

**The missing join key for agentic-action evidence. It works with whatever
you already issue; it replaces nothing.**

Permits, receipts, outcome attestations, delegation chains, payment
mandates, consent records, audit events, insurance objects often reference
"the action" using format-local objects and digests. Without an agreed
material-action definition, a permit
from one system, an approval from a second, and an outcome attestation from
a third cannot be composed as evidence about the same action without
bilateral negotiation, and each artifact is only as strong as whatever
fields its author happened to digest.

CAID addresses both problems with one small object and one string:

```json
{
  "action_type": "payment.release.1",
  "amount": "40000.00",
  "currency": "USD",
  "beneficiary_account": "sha256:7c9e...beef",
  "payment_instruction_id": "pi_42"
}
```

    caid:1:payment.release.1:jcs-sha256:Kq3v...N9w

- **Typed**: `action_type` is inside the digested content and names an
  entry in the action-type registry (or a local definitions file in the
  same schema). Each type declares its REQUIRED material fields, so a
  conforming issuer cannot mint an identifier for an underspecified action.
  This is the unilateral win: your artifact stops being challengeable on
  "the digest did not cover the amount."
- **Replayable enums**: inline enums are closed sets. External enums resolve
  only through a locally supplied snapshot whose reference, edition label,
  and SHA-256 pin all match the type definition. Mutable names, missing
  snapshots, digest mismatches, and out-of-set values fail closed without a
  network fetch.
- **Joinable**: under the selected suite and pinned type definition, matching
  CAIDs commit to matching canonical typed content. Each artifact still
  verifies under its own specification and trust boundary. A shared action
  identifier reduces bilateral correlation work; it does not guarantee that
  two deployments selected equivalent type definitions or mapping profiles.
- **Mappable without guessing**: when native formats cannot emit identical
  bytes, a relying-party-pinned Action-Mapping Profile projects each verified
  source into a material CAID action. The comparison returns
  `EQUIVALENT_UNDER_PROFILE`, `NOT_EQUIVALENT`, or `INDETERMINATE`; missing or
  lossy mappings abstain.
- **Boring on purpose**: no trust semantics, no assurance levels, no
  authorization logic, no network dependency, no fees. Registry data is
  CC0. Reference implementations (JavaScript, Python, Go) are Apache-2.0,
  dependency-free, and agree on a shared conformance vector suite.

## The verification boundary

CAID mapping starts only after each source artifact has verified under its
own specification and trust anchors. A mapping profile binds an exact source
media type, schema, version, transform set, and target action type. The
relying party pins the profile hash. Mapping never upgrades an untrusted
artifact into trusted evidence and never converts equivalence into
authorization.

Run the signed cross-format demonstration:

```sh
node examples/caid-action-mapping.mjs
```

It accepts two independently signed native objects only after native
verification and refuses or abstains on signature tampering, merchant
substitution, profile substitution, and missing native verification.

## What a CAID is not

A CAID commits an identifier to canonical typed content. It does not
prove the action was authorized, executed, safe, or wise. It is not a
capability: treat it as public. Composition joins on the identifier; no
verifier ever ingests another verifier's evidence into its own trust
boundary.

## Layout

- `DESIGN.md` — normative core
- `../standards/posted/draft-schrock-canonical-action-identifier-02.xml` —
  published individual Internet-Draft source (xml2rfc v3)
- `registry/` — action-type registry seed, suites, governance
- `impl/js`, `impl/python`, `impl/go` — reference implementations
- `conformance/vectors.json` — 88 core identifier vectors (corpus version 3),
  including pinned, unresolved, mismatched, and out-of-set enum cases,
  compact-inline trimming, own-member presence, unpaired-surrogate
  refusals, whole-string grammar refusals (a trailing line feed in an amount,
  digest field, timestamp, action type, suite, or CAID digest), and
  value-based integer-field cases
- `conformance/mapping-vectors.json` — 25 cross-format mapping vectors,
  including the SILP IR to CAID `CANCEL+EMAIL` profile and trailing line
  feeds in a JSON Pointer array index and a target field name
- `interop/consequential-action-v1/` — 25 candidate, revision-pinned
  mechanism mappings with 100 positive, refusal, and abstention vectors;
  all await author review
- `bindings/` — one-page composition notes for existing specs (MCP, A2A,
  AP2, AuthZEN, ACTA, WIMSE, permit receipts, outcome attestation, OAuth
  agent-authorization drafts, AGTP, EMILIA receipts, Continuum)

Stewardship: currently maintained by EMILIA Protocol with a standing
commitment, stated in `registry/GOVERNANCE.md`, to transition the registry
to IANA or another neutral body upon adoption.

## Registry v4 migration

Registry v4 adds an immutable `2026-09-17` SIX ISO 4217 snapshot. A currency
action object whose code is in that snapshot produces the same CAID bytes as
before. A code that registry v3 accepted but the snapshot does not list (for
example `BGN`, `HRK`, or `ZZZ`) is refused under v4. Issuers and verifiers must
move their registry pin from v3 to v4 and supply the referenced snapshot.

What else now refuses, in every implementation:

- a v3-style bare external `values_ref`, and an unresolved or
  digest-mismatched one, whenever the field is present;
- a value outside a compact `inline:` list. The v3-era implementations
  accepted any string there; there are 15 such fields across 15 registered
  types, and local definitions using the form are affected the same way;
- an enum definition in none of the three forms DESIGN.md section 3 allows,
  including a `values` or `values_ref` member written as `null`; and
- a string or member name containing an unpaired surrogate
  (`unsupported_value`).

Eleven active types cannot produce or verify any CAID under registry v4,
because a required field references an external code set that has no pinned
snapshot yet: `payment.refund.1`, `ach.debit.originate.1`, `key.create.1`, `key.rotate.1`, `dns.record.delete.1`, `firewall.rule.open.1`, `pii.export.1`, `rx.dispense.1`, `prior.auth.approve.1`, `phi.disclose.1`, and `vendor.onboard.1`. The registry lists their twelve fields in
`unresolved_external_enums`, and `npm run caid:conformance` fails if that list
drifts. They need a reviewed value-set snapshot before use. The ISO 4217
snapshot is List One verbatim, so it also contains codes such as `XXX` (no
currency involved) and `XTS` (reserved for testing); a type that must exclude
them needs its own narrower pinned set in a new type version.

Historical v3 decisions remain v3 decisions. The v4 code refuses v3's bare
external references, so replaying a v3 decision requires the v3 registry and
the pre-v4 implementations together, for example from commit `f46328afc`, the
last `main` commit before registry v4. The version 1 core corpus from that
commit is recorded by digest in `conformance/vectors.json`, as is the
version 2 corpus that preceded the whole-string grammar and integer-field
vectors.
