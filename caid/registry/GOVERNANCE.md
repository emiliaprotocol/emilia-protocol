# CAID Registry Governance

This document governs the two registries in this directory:
`action-types.json` (registered action types) and `suites.json`
(canonicalization and digest suites).

One sentence of scope before anything else: CAID and its registries carry
no trust semantics. A registered type defines WHAT must be inside the
digested content of an action object, never whether the action was
authorized, executed, safe, or wise. Registration is a naming and schema
act, not an endorsement of any product, practice, or party.

## 1. Naming grammar

A registered action type name is a sequence of lowercase dotted segments
whose final segment is an integer type version:

    name        = segment 1*("." segment) "." version
    segment     = lowercase-alpha *(lowercase-alpha / digit / "-")
    version     = 1*digit          ; integer, starts at 1, no leading zeros

Examples: `payment.release.1`, `dns.record.delete.1`, `rx.dispense.1`.

Rules:

- Segments are lowercase ASCII. No uppercase, no underscores, no empty
  segments, no leading or trailing dots.
- Names read general-to-specific left to right: domain, then object, then
  verb (`payment.release`, `firewall.rule.open`). New registrations should
  follow the existing domain prefixes where one fits (`payment.*`, `iam.*`,
  `dns.*`, `key.*`, ...) and introduce a new first segment only when none
  does.
- The version is part of the name. `payment.release.1` and
  `payment.release.2` are distinct types that can coexist in the registry.

## 2. Change policy: validation semantics are immutable

Once a type version is published as `active`, every field that affects
validation or material meaning is immutable. A verifier replaying an old
artifact against the same versioned definition must get the same result.

- Required and optional field declarations MUST NOT be added, removed,
  reordered, retyped, or semantically redefined within an active version.
- Normalization rules, enum sets, and `digest_notes` MUST NOT change within
  an active version.
- Non-normative references and editorial summaries MAY be corrected only
  when the change cannot alter validation or interpretation.
- Status MAY move from `active` to `deprecated`; deprecation never makes an
  old object cryptographically invalid.

## 3. Breaking changes are a new version

Any of the following requires publishing a NEW version of the type
(`.2`, `.3`, ...):

- removing a field,
- adding a required or optional field,
- changing a field's type,
- changing a field's meaning or normalization rule,
- changing the enum code set a values_ref points at in a non-additive way.

Old versions are never deleted. A superseded version's status moves from
`active` to `deprecated`; deprecated types still validate, and verifiers
decide their own policy toward them. Status values: `active`,
`deprecated`.

## 4. Local definitions use the same schema

The type entry schema (DESIGN.md section 3, mirrored by every entry in
`action-types.json`) is normative for LOCAL definition files too. A
private deployment defines its own types in a file of the same shape and
configures its issuers and verifiers with it.

There is no reserved private-use syntax, no `x-` prefix, no private name
range. The distinction is presence: a type is either present in a
definition source the verifier is configured with (this public registry,
or a local file in the same schema) or it is unknown. Unknown types are a
refusal for conforming issuers; for verifiers, accepting unregistered
types is an explicit configuration knob, default off.

A locally defined name that later gets registered publicly with a
different schema is ambiguous and MUST NOT be treated as interoperable,
even when an individual object happens to have the same digest. Local
deployments SHOULD use an organization-specific first segment (for example,
`acmecorp.ledger.close.1`) and MUST pin the exact definition source or
registry snapshot used for cross-domain comparison.

## 5. Registering a new type: process and quality bar

Additions go through public review. The proposal is the completed entry
itself, in the normative schema, plus a short rationale. Review is on the
mailing list or issue tracker of wherever this registry is homed at the
time (see section 7).

The quality bar is the material-fields test:

- Every required field must be MATERIAL: a field is material when two
  actions differing only in that field are different actions that a
  reviewer, auditor, or counterparty would need to distinguish.
- Amounts and fractional quantities are `amount-string`, never JSON
  numbers.
- Identifiers that are PII or secret-adjacent (account numbers, patient
  identifiers, personal emails, tax IDs, authorization codes) are
  `digest` typed, with the normalization rule stated in notes. Raw
  personal data and secrets never sit in an action object.
- Enums carry a `values_ref` naming a real code set (an ISO standard, an
  IANA registry, a regulator's catalog) or an explicit inline list.
- Timestamps are RFC 3339 UTC with `Z`; date-only values are strings with
  an ISO 8601 date note.
- A practitioner from the type's industry should recognize the fields as
  the ones that matter. Entries that an expert would call decorative,
  incomplete, or wrongly typed are returned for revision, not registered.

There are no fees for registration, use, or anything else. There never
will be under this governance.

## 6. Licensing

- Registry data (`action-types.json`, `suites.json`, and this document)
  is dedicated to the public domain under CC0-1.0.
- Reference implementation code in this package is licensed Apache-2.0.

Anyone may copy, embed, subset, or extend the registry data in any
product without permission or attribution.

## 7. Stewardship and transition

This registry is currently maintained by the EMILIA Protocol maintainers
as its initial editors; that is the extent of any product affiliation,
and nothing in the registry depends on or references any vendor's
protocol.

The maintainers commit to transitioning stewardship of the registries to
IANA (as IETF-managed registries with a designated-expert or
specification-required policy) or to another neutral standards
development organization, upon meaningful multi-party adoption or upon
adoption of the CAID specification by a standards body, whichever comes
first. The registry format has been kept deliberately simple (flat JSON,
CC0) so that such a transition is a copy, not a migration.

## 8. Related work

- IANA operates many protocol registries, including the Well-Known URIs
  registry. The authors are not aware of an IANA registry that enumerates
  typed business or agent action families together with required material
  fields. This registry is designed for transition to IANA or another
  neutral standards body (section 7), subject to community review.
- The CSA/Vanta AARM draft defines a runtime action EVENT schema (what an
  agent did, observed at runtime) but explicitly does not enumerate action
  types or their required fields. The two are complementary: an AARM-style
  event can carry a CAID to say WHICH typed action content it concerns.
- Artifact-level specifications (permits, receipts, attestations,
  delegation, consent evidence) each define their own trust semantics.
  CAID deliberately defines none: it is the join key those artifacts can
  share, and each artifact still verifies inside its own trust boundary
  under its own specification.
