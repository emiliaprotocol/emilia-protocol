# CAID Registry Governance

This document governs the registries in this directory:
`action-types.json` (registered action types) and `suites.json`
(canonicalization and digest suites), together with the value-set files
under `value-sets/`, the frozen registry versions under `history/`, and
`digests.json`. The processing rules themselves are normative in
`draft-schrock-canonical-action-identifier-05`; `../spec/` holds the same
rules as derived, machine-read data (`core.json`) and grammar (`caid.abnf`).

One sentence of scope before anything else: CAID and its registries carry
no trust semantics. A registered type defines WHAT must be inside the
digested content of an action object, never whether the action was
authorized, executed, safe, or wise. Registration is a naming and schema
act, not an endorsement of any product, practice, or party.

## 1. Naming grammar

A registered action type name matches the `action-type` rule of the draft's
Appendix A (`../spec/caid.abnf`): lowercase dotted name segments followed by
a positive integer type version with no leading zero. The grammar admits a
single name segment; registration additionally requires at least two.

Examples: `payment.release.1`, `dns.record.delete.1`, `rx.dispense.2`.

Rules:

- Segments are lowercase ASCII letters, digits and hyphens, starting with a
  letter. No uppercase, no underscores, no empty segments, no leading or
  trailing dots.
- Names read general-to-specific left to right: domain, then object, then
  verb (`payment.release`, `firewall.rule.open`). New registrations should
  follow the existing domain prefixes where one fits (`payment.*`, `iam.*`,
  `dns.*`, `key.*`, ...) and introduce a new first segment only when none
  does.
- The version is part of the name. `payment.release.1` and
  `payment.release.2` are distinct types that coexist in the registry.

## 2. Change policy: validation semantics are immutable

Once a type version is published, every field that affects validation or
material meaning is immutable, with one exception for enum pins (the
monotone advance below). A verifier replaying an old artifact against the
same versioned definition gets the same result.

- Required and optional field declarations MUST NOT be added, removed,
  reordered, retyped, or semantically redefined within a published version.
- Normalization rules and `digest_notes` MUST NOT change within a published
  version.
- A human-readable external enum name is not an immutable set. External enums
  MUST name an edition or snapshot and pin the SHA-256 digest of the RFC 8785
  canonical JSON values array. A verifier resolves only an exact
  `values_ref` / `values_snapshot` / `values_sha256` match and verifies the
  digest locally. Missing, unresolved, or mismatched pins fail closed.
- Each governed value-set file is listed in `enum_snapshot_files` with its
  three labels, its `path` under `value-sets/`, `snapshot_sha256` (the
  SHA-256 of the RFC 8785 canonical JSON of the whole file), and its
  `source_url`, `retrieved` date and `license`. `snapshot_sha256` binds the
  file's provenance members (source URL and digest, publication and
  retrieval dates, `hash_input`, `derivation`, `@version`) to the registry,
  so they cannot change without a new registry version. Re-deriving the
  values from the upstream source still means fetching that source and
  comparing it with `source_sha256`; `derive-v5.mjs` does this for the v5
  value sets.
- Monotone pin advance. A new registry version MAY advance the value-set
  pin of an enum field in place, without a new type version, only to a later
  edition that contains every member of the set the field accepted before.
  The first pin of a field that previously resolved no set is such an
  advance, because the field accepted no value. Removing, renaming, or
  redefining a member is never an advance and needs a new type version
  (section 3). Every advance is recorded field by field in the migration
  section of the registry version that makes it, and it changes the type's
  `definition_sha256`.
- Definition digest. Every type has a `definition_sha256`: `sha256:` and the
  lowercase hexadecimal SHA-256 of the RFC 8785 encoding of its validation
  projection (`action_type`, `required_fields`, `optional_fields` with an
  absent list read as `[]`, and every field entry without its `notes`).
  `digests.json` lists it for every type, and compute and verify results
  report it. Because of the monotone advance, an object valid under one
  registry version stays valid under every later one for a relying party
  that does not pin. A relying party that needs exact reproducibility pins
  `definition_sha256`, and verification refuses any other definition as
  `definition_mismatch`.
- Non-normative references and editorial summaries MAY be corrected only
  when the change cannot alter validation or interpretation.
- Status MAY move from `active` to `deprecated`. Status never affects
  computation or verification: a deprecated type still resolves, computes
  and verifies wherever its fields resolve, and deprecation never makes an
  old object invalid. `supersedes` (on the successor) and `superseded_by` (on
  the predecessor) are informative and outside `definition_sha256`.
- Every published registry version is kept byte-identical at
  `history/action-types.v<N>.json`. A consumer that pinned the bytes of a
  registry version reads that file; its pin never breaks.

## 3. Breaking changes are a new version

Any of the following requires publishing a NEW version of the type
(`.2`, `.3`, ...):

- removing a field,
- adding a required or optional field,
- changing a field's type,
- changing a field's meaning or normalization rule,
- changing an enum set in any way other than a monotone advance (section 2).

A new validation constraint on an existing field type is always a new field
type, never a new member on an existing type: implementations of an earlier
revision ignore unknown members, so they would accept what a later one
refuses, while an unknown field type makes them refuse.

## 3.1 Registry v3 to v4 corrective migration

Registry v3 named external enum sources but did not identify an immutable
edition or provide bytes that a verifier could integrity-check. Implementations
therefore could not enforce those fields consistently. Registry v4 did not
silently reinterpret the file labeled v3: it was a new registry snapshot that
pinned these fields to the set their existing names already denoted:

- the `currency` field of the 10 types that carry one
  (`payment.release.1`, `payment.refund.1`, `payout.batch.execute.1`,
  `wire.transfer.1`, `ach.debit.originate.1`, `order.place.1`,
  `refund.issue.1`, `contract.execute.1`, `benefit.disburse.1`, and
  `invoice.approve.1`), pinned to the `2026-09-17` SIX ISO 4217 List One
  value set; and
- `rx.dispense.1` `daw_code`, from the bare label "NCPDP Dispense As Written
  codes 0-9" to the inline list `0 | 1 | ... | 9` that label names.

The action objects and resulting CAID strings for values in those sets did
not change. A currency code that v3 accepted but List One omits (for example
`BGN` or `HRK`) refuses under v4 and later. List One is pinned verbatim, so it
includes codes such as `XXX` (no currency involved), `XTS` (reserved for
testing), and the precious-metal codes; a type that must exclude them needs
its own narrower set in a new type version. v3 to v4 remains the only
migration that removed accepted values; its decisions remain v3 decisions.

Under v4, a bare v3-style external `values_ref`, an unresolved snapshot, a
digest mismatch, a value outside the set, and a value outside a compact
`inline:` list all refuse as `mistyped_field:<name>`. Historical decisions
made with registry v3 remain decisions under that pinned historical registry;
callers MUST NOT report them as v4 validation without replaying them, and
replay needs the v3 registry with the pre-v4 implementations (for example
from commit `f46328afc`).

Under v4, twelve required external references had no reviewed snapshot, so
11 types could not produce or verify any CAID: `payment.refund.1`,
`ach.debit.originate.1`, `key.create.1`, `key.rotate.1`,
`dns.record.delete.1`, `firewall.rule.open.1`, `pii.export.1`,
`rx.dispense.1`, `prior.auth.approve.1`, `phi.disclose.1`, and
`vendor.onboard.1`. Registry v5 resolves all twelve (section 3.2).

## 3.2 Registry v4 to v5

Registry v4 is frozen byte-for-byte at `history/action-types.v4.json`
(SHA-256 `73a31f4a4156e3de02e1c3a9ef355f73c07ba25e6b1bb3da8fde8677c2e23d26`).
Every pin of the v4 bytes points at that file. `derive-v5.mjs` rebuilds v5
from it and the upstream files; `check.mjs` checks every rule below.

First pins (monotone advances from a field that accepted nothing). Both
types keep their version and now compute:

- `dns.record.delete.1` `record_type`: the IANA DNS Resource Record TYPEs
  registry, file updated 2026-08-28, 99 mnemonics verbatim
  (`value-sets/iana-dns-rr-types.2026-08-28.json`). `definition_sha256`
  moves from `sha256:9bb2d982...` to `sha256:0b320a2b...`.
- `vendor.onboard.1` `jurisdiction`: the 249 officially assigned ISO 3166-1
  alpha-2 codes as carried by the IANA Language Subtag Registry, File-Date
  2026-09-17 (`value-sets/iso-3166-1-alpha-2.2026-09-17.json`). ISO asserts
  copyright in the ISO 3166 lists; no list was taken from ISO.
  `definition_sha256` moves from `sha256:3c3f77e0...` to
  `sha256:716562ad...`.

New type versions using existing field types, each superseding a
deprecated `.1`:

- `key.create.2` and `key.rotate.2`: the algorithm is an enum pinned to the
  IANA JSON Web Signature and Encryption Algorithms registry (53 names, file
  updated 2026-05-22), with optional key size and curve fields (the curve
  pinned to the IANA JSON Web Key Elliptic Curve registry, 8 names).
- `firewall.rule.open.2`: `protocol` is `any` or a decimal IPv4 Protocol /
  IPv6 Next Header number `0` to `255`.
- `pii.export.2`: `legal_basis` is one of the six GDPR Article 6(1) bases or
  `not-subject-to-gdpr`.
- `phi.disclose.2`: `purpose` is one of 23 purposes from 45 CFR 164.502 to
  164.514.

New type versions using `code` fields, each superseding a deprecated `.1`:

- `payment.refund.2` `reason_code`: format `iso20022-external-code`.
- `ach.debit.originate.2` `sec_code`: format `nacha-sec`.
- `rx.dispense.2` `ndc_code`: format `ndc-11`.
- `prior.auth.approve.2` `service_code` (format `hcpcs`) and
  `diagnosis_code` (format `icd-10-cm`).

`contract.execute.2` requires both `contract_value` (amount-string) and
`currency` (the pinned ISO 4217 set), with no sentinel value.
`contract.execute.1` stays active for contracts that state no monetary
value.

The nine superseded `.1` types are deprecated with `superseded_by`. They
still resolve, compute and verify wherever their fields resolve, but each
has a required field whose external set was never pinned (listed in
`unresolved_external_enums`, all on deprecated types), so none of them can
compute. Registry v5 has 62 types: 53 active, every one of which computes,
and 9 deprecated.

## 4. Local definitions use the same schema

The type definition schema (draft Section 4.2; `../spec/core.json`
`definition`) is normative for LOCAL definition files too. A private
deployment defines its own types in a file of the same shape and configures
its issuers and verifiers with it.

A definition conforms only if `required_fields` is a non-empty array,
`optional_fields` is absent or an array, every field entry is an object with
a string `type` and a `name` that is a non-empty string without `:`, other
than `action_type`, and unique across both lists, and every entry of a
registered field type carries only that type's members. A definition that
does not conform, or two configured definitions of one type whose
`definition_sha256` differ, refuse as `invalid_definition`.

There is no reserved private-use syntax, no `x-` prefix, no private name
range. The distinction is presence: a type is either present in a
definition source the issuer or verifier is configured with (this public
registry, or a local file in the same schema) or it is unknown. Unknown
types refuse as `unknown_action_type`, for issuers and verifiers alike.

A locally defined name that later gets registered publicly with a
different schema is ambiguous and MUST NOT be treated as interoperable,
even when an individual object happens to have the same digest. Local
deployments SHOULD use an organization-specific first segment (for example,
`acmecorp.ledger.close.1`) and MUST pin the exact definition source,
registry snapshot, or `definition_sha256` used for cross-domain comparison.

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
  personal data and secrets never sit in an action object. A digest of a
  low-entropy identifier is still guessable; see the draft's Privacy
  Considerations.
- A type added after registry version 5 whose required fields can all be
  low-entropy requires a member that carries at least 128 bits of entropy,
  such as a random instruction or occurrence identifier from the system of
  record, unless its `digest_notes` or its specification state why not.
  This is the criterion of the draft's Section 12.2. The types of registry
  version 5 predate it; for the 54 of them that IANA is asked to register,
  the draft's Privacy Considerations state why their identifiers are not
  required to carry that entropy.
- Enums carry a non-empty inline list, or an external `values_ref` plus an
  immutable edition/snapshot, a canonical values array, and its verified
  SHA-256 pin. A mutable standard, registry, catalog, or URL by itself is not
  sufficient. No active type may carry an unresolved external enum. A
  proposal that pins an external enum supplies the snapshot file, in the
  shape the draft's Section 4.4 gives, with the source it was derived from
  and what is known of that source's terms, and the SHA-256 digest of the
  file; review confirms that the file is publicly available under the
  terms it states before the entry is registered.
- Values from a large, changing, or licensed code system use a `code`
  field: `code_system` (an absolute URI naming the system) and `format` (a
  code format of the CAID Code Formats registry, whose initial entries are
  part A.4 of the draft's Appendix A). CAID pins syntax and
  system only, never a value set, and never snapshots such a system. CPT is
  licensed by the American Medical Association: no CPT code, descriptor, or
  value set may appear in this registry, its vectors, or its value sets.
  `code_systems` records every system a field names, with its sources.
- A new code format is added to `../spec/caid.abnf` and must pass
  `../spec/abnf-check.mjs`, which proves it finite, free of nested or
  overlapping quantifiers, and linear-time in JavaScript, Python and Go.
- Timestamps are RFC 3339 UTC with `Z`; date-only values are strings with
  an ISO 8601 date note.
- A practitioner from the type's industry should recognize the fields as
  the ones that matter. Entries that an expert would call decorative,
  incomplete, or wrongly typed are returned for revision, not registered.

There are no fees for registration, use, or anything else. There never
will be under this governance.

## 6. Licensing

- Registry data (`action-types.json`, `suites.json`, `value-sets/`,
  `history/`, `digests.json`, and this document) is dedicated to the public
  domain under CC0-1.0. The dedication covers only the maintainers' rights;
  each value-set file and `code_systems` entry records the upstream source
  and what is known of its terms.
- Reference implementation and tooling code in this package is licensed
  Apache-2.0.

Anyone may copy, embed, subset, or extend the registry data in any
product without permission or attribution.

## 7. Stewardship and transition

This registry is maintained by the EMILIA Protocol maintainers as its
initial editors; that is the extent of any product affiliation.

The -05 revision of the CAID draft asks IANA to create seven registries:
CAID Suites, CAID Action Types, CAID Field Types, CAID Code Formats, CAID
Reason Codes, CAID Mapping Transforms, and CAID Mapping Loss Policies.
IANA provisionally registered the separate `canactid` URI scheme on
2026-10-05 with CAID-05 as its reference. Provisional scheme registration
does not create these registries, constitute permanent registration, or
signal IETF adoption or endorsement. Until IANA creates the
registries, the reference copies are `suites.json` and `action-types.json`
in this directory for the first two, and `../spec/core.json` with
`../spec/caid.abnf` for the other five. The registry format has been kept
deliberately simple (flat JSON, CC0) so that such a transition is a copy,
not a migration.

## 7.1 Types that IANA is not asked to register

Registry version 5 carries eight types that do not belong under IETF change
control. They are not among the initial entries the draft asks IANA to
register; the draft lists them apart, in its Appendix D.2:

- `emilia.mobile.authorized-action.1`: named for a product, and its meaning
  comes from a vendor specification (`mobile/spec/EP-MOBILE-CEREMONY-v1.md`
  in this repository).
- `agent.state.export.1`, `agent.state.import.1`,
  `agent.state.key-release.1`, and `agent.state.retire-source.1`: defined
  by `EP-PORTABLE-STATE-HANDOFF-v0.1`.
- `science.bio.experiment.execute.1`: defined by the Model-to-Matter
  Internet-Draft (`draft-schrock-model-to-matter`).
- `travel.cancel-notify.1`: defined by the SILP Internet-Draft
  (`draft-hwang-silp-protocol`), another author's document.
- `dns.zone.transfer.1`: the name reads as a DNS zone transfer (AXFR or
  IXFR), but the type is an EPP registrar transfer of a domain (RFC 5730).
  A registered name is never reassigned, so the misnomer stays out of the
  IANA registry.

No other type is named for a vendor or product, or cites a vendor
specification.

These eight stay in registry version 5 unchanged, and they resolve, compute
and verify like every other type. Removing one would make objects that are
valid under registry version 4 invalid (section 2), and the draft pins the
SHA-256 of `action-types.json`. Once IANA creates the CAID Action Types
registry, each of the seven types defined by another specification can be
registered under its Specification Required policy, with its own
specification and its own change controller, which need not be the IETF.
The draft's designated expert does not register a name whose first segment
is organization-specific unless that organization is the change controller,
so `emilia.mobile.authorized-action.1` can be registered only with its
organization as change controller.
`dns.zone.transfer.1` is not a candidate: a registered name is never
reassigned, so the path for the registrar-transfer type is a successor
whose name describes it, citing RFC 5730 and RFC 5731, in a later registry
version. The IETF is the change controller of the initial entries the
draft registers, and of no other entry. Because the draft pins the bytes of
registry version 5, even an editorial correction to these entries, such as
a change controller or a newer revision of a cited draft, waits for a later
registry version.

`scripts/check-caid-04.mjs` holds the same list as `IANA_EXCLUDED` and
fails if the draft's Appendix D or its counts diverge from it.

## 8. Related work

- IANA operates many protocol registries, including the Well-Known URIs
  registry. The authors are not aware of an IANA registry that enumerates
  typed business or agent action families together with required material
  fields.
- The CSA/Vanta AARM draft defines a runtime action EVENT schema (what an
  agent did, observed at runtime) but explicitly does not enumerate action
  types or their required fields. The two are complementary: an AARM-style
  event can carry a CAID to say WHICH typed action content it concerns.
- Artifact-level specifications (permits, receipts, attestations,
  delegation, consent evidence) each define their own trust semantics.
  CAID deliberately defines none: it is the join key those artifacts can
  share, and each artifact still verifies inside its own trust boundary
  under its own specification.
