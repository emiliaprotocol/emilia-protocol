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
- A human-readable external enum name is not an immutable set. External enums
  MUST name an edition or snapshot and pin the SHA-256 digest of the RFC 8785
  canonical JSON values array. A verifier resolves only an exact
  `values_ref` / `values_snapshot` / `values_sha256` match and verifies the
  digest locally. Missing, unresolved, or mismatched pins fail closed.
- Each governed value-set file is listed in `enum_snapshot_files` with its
  three labels, its `path` under `value-sets/`, and `snapshot_sha256`, the
  SHA-256 of the RFC 8785 canonical JSON of the whole file. The last pin binds
  the file's provenance members (source URL and digest, publication and
  retrieval dates, `hash_input`, `@version`) to the registry, so they cannot
  change without a new registry version. The pin makes the file's provenance
  record tamper-evident; re-deriving the values from the upstream source still
  means fetching that source and comparing it with `source_sha256`.
- Corrective pin exception. A new registry version MAY replace the
  machine-readable pin of a value set that an active type already names,
  without a new type version, only when the pin identifies the set the
  existing name already denoted, and the migration is documented field by
  field, including every type whose ability to compute changes. Changing
  which values the name denotes, or adding or removing values, is never a
  correction and needs a new type version (section 3). Section 3.1 records
  the only use of this exception so far.
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

Additive upstream code-set changes also require a new action-type version if
the accepted array changes. The point of the pin is that validation remains
replayable; an upstream maintainer's compatibility policy cannot silently
alter an active CAID type.

## 3.1 Registry v3 to v4 corrective migration

Registry v3 named external enum sources but did not identify an immutable
edition or provide bytes that a verifier could integrity-check. Implementations
therefore could not enforce those fields consistently. Registry v4 does not
silently reinterpret the file labeled v3: it is a new registry snapshot that
uses the corrective pin exception in section 2 for these fields:

- the `currency` field of the 10 active types that carry one
  (`payment.release.1`, `payment.refund.1`, `payout.batch.execute.1`,
  `wire.transfer.1`, `ach.debit.originate.1`, `order.place.1`,
  `refund.issue.1`, `contract.execute.1`, `benefit.disburse.1`, and
  `invoice.approve.1`), pinned to the `2026-09-17` SIX ISO 4217 List One
  value set; and
- `rx.dispense.1` `daw_code`, from the bare label "NCPDP Dispense As Written
  codes 0-9" to the inline list `0 | 1 | ... | 9` that label names.

The action objects and resulting CAID strings for values in those sets do not
change. A currency code that v3 accepted but List One omits (for example `BGN`
or `HRK`) refuses under v4. List One is pinned verbatim, so it includes codes
such as `XXX` (no currency involved), `XTS` (reserved for testing), and the
precious-metal codes; a type that must exclude them needs its own narrower set
in a new type version.

Issuers and verifiers moving to v4 MUST pin the v4 registry snapshot and load
the referenced value-set artifact. A bare v3-style external `values_ref`, an
unresolved snapshot, a digest mismatch, a value outside the set, and a value
outside a compact `inline:` list all refuse as `mistyped_field:<name>`. The
v3-era implementations did not enforce `inline:` lists either; v4 enforces
all 15 of them. Historical decisions made with registry v3 remain decisions
under that pinned historical registry; callers MUST NOT report them as v4
validation without replaying them, and replay needs the v3 registry with the
pre-v4 implementations (for example from commit `f46328afc`).

Twelve external references in active types still have no reviewed snapshot.
They are listed in `unresolved_external_enums` and refuse whenever present.
All twelve are required fields, so these 11 types cannot produce or verify any
CAID under v4: `payment.refund.1`, `ach.debit.originate.1`, `key.create.1`,
`key.rotate.1`, `dns.record.delete.1`, `firewall.rule.open.1`,
`pii.export.1`, `rx.dispense.1`, `prior.auth.approve.1`, `phi.disclose.1`, and
`vendor.onboard.1`. Each needs a reviewed value-set artifact before use. They
stay `active` because their definitions are unchanged; they are not counted as
usable, and `npm run caid:conformance` fails if the list drifts from the
registry. `contract.execute.1` keeps `currency` optional beside an optional
`contract_value`; requiring it is a validation change and needs
`contract.execute.2`.

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
- Enums carry a non-empty inline list, or an external `values_ref` plus an
  immutable edition/snapshot, a canonical values array, and its verified
  SHA-256 pin. A mutable standard, registry, catalog, or URL by itself is not
  sufficient. The fields in `unresolved_external_enums` predate this bar and
  do not meet it; section 3.1 lists the types they block.
- Timestamps are RFC 3339 UTC with `Z`; date-only values are strings with
  an ISO 8601 date note.
- A practitioner from the type's industry should recognize the fields as
  the ones that matter. Entries that an expert would call decorative,
  incomplete, or wrongly typed are returned for revision, not registered.

There are no fees for registration, use, or anything else. There never
will be under this governance.

## 6. Licensing

- Registry data (`action-types.json`, `suites.json`, `value-sets/`, and this document)
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
