# CAID — Canonical Action IDentifier (v1 normative design)

Date: 2026-07-14. Author: EMILIA Protocol maintainers.
This file is the normative core. Every implementation, vector, draft, and
binding in this directory conforms to THIS file. Change it here first.

## What this is, in one paragraph

Artifacts for permits, receipts, outcome attestations, delegation chains,
mandates, consent evidence, and insurance frequently reference "the action"
using format-local content or digests. CAID defines one interoperable form: a typed action object, a
canonicalization+digest suite, and a compact identifier string, plus a
registry of action types with REQUIRED material fields. It carries zero trust
semantics. It is not authorization, identity, or proof of execution. It is a
join key: matching CAIDs commit to matching canonical typed content under the
selected suite and pinned type definition, while each artifact still verifies
in its own trust boundary.

## Design goals (the adoption physics)

1. UNILATERAL VALUE FIRST: adopting CAID hardens the adopter's OWN artifact
   against the "digest over {action:'wire'} binds nothing" failure. The
   material-fields validation is the selfish reason to adopt before any
   network exists.
2. ZERO THREAT SURFACE: no assurance classes, no receipts, no verification
   semantics beyond digest recomputation. Nothing in the core that a vendor
   would perceive as a competitor's trust model.
3. COSTLESS ADOPTION: one field in the object, one string in the artifact,
   one lookup table. A conforming issuer is ~200 lines in any language.
4. NEUTRAL HOME: registry data CC0, code Apache-2.0, governance doc commits
   to transition to IANA or a neutral SDO on adoption.
5. WORKS INSIDE A WALLED GARDEN DAY ONE: the type-definition SCHEMA is
   normative; the public registry is one source of definitions; a private
   deployment can carry pinned local definitions in the same format. (This defuses
   the "single-winner world doesn't need joins" attack: CAID is useful with
   N=1, invaluable with N>=2.)

## 1. The action object

A JSON object (or CBOR map under a cbor suite) that:

- MUST contain `action_type`: a registered or locally-defined versioned type
  name (see section 3). The type is INSIDE the digested content, so the
  identifier's type cannot be swapped without changing the digest.
- MUST contain every REQUIRED material field of that type, encoded per the
  type definition's field types (section 4).
- MAY contain additional fields. Extra fields are covered by the digest.
- MUST NOT encode money or quantity values as JSON numbers where the type
  definition declares them `amount-string` (float/precision malleability).
- Numbers follow the VALUE-BASED rule: a JSON number is accepted iff its
  IEEE 754 double value is an integer with magnitude at most 2^53-1, and
  it serializes as that integer in plain decimal. Literal form is
  irrelevant ("1e3" and "2.0" are the integers 1000 and 2, exactly as
  ECMAScript's JSON.parse sees them); fractional, NaN, infinite, and
  out-of-range values refuse as `unsupported_number` in every conforming
  implementation. Rationale: ECMAScript number serialization is the
  leading cross-language canonicalization divergence; a value-based rule
  is the only one all languages can implement identically, and fractional
  quantities are strings by design.

The object identifies material action content. Pre-execution
artifacts (permits, challenges, receipts) and post-execution artifacts
(outcome attestations, audit records, reliance events) all reference the
same object by CAID.

## 2. Suites and the identifier

Suite registry (registry/suites.json):

- `jcs-sha256`  — RFC 8785 JSON Canonicalization Scheme -> SHA-256 (RFC 6234).
  REQUIRED for conforming implementations.
- `cbor-sha256` — RFC 8949 section 4.2 core deterministic encoding -> SHA-256.
  DEFINED in v1; implementations MAY support it. (Reference impls here ship
  jcs-sha256 only; say so honestly everywhere.)

Digest: `digest = SHA-256(canonical_bytes(action_object))`. NO domain
separation prefix, deliberately: the object is self-typed via `action_type`,
and the whole point is that rival artifacts can adopt the identical digest
they may already compute over canonical bytes. Conforming verifiers MUST
check the in-object `action_type` equals the CAID's type; that check is
where cross-context reinterpretation dies, not in a byte prefix. (Security
considerations must state this trade explicitly.)

String form (strict ABNF in the I-D):

    caid:1:<action_type>:<suite>:<digest-b64url>

- `1` is the CAID version.
- `<action_type>` lowercase dotted segments, final segment is the integer
  type version, e.g. `payment.release.1`.
- `<suite>` from the suite registry, lowercase.
- `<digest-b64url>` RFC 4648 section 5, unpadded, case-sensitive.
- Parsers are STRICT: refuse padding, refuse uppercase in type/suite, refuse
  empty segments, refuse anything after the digest. Unknown version or suite
  is a refusal, never a guess.

Equality: two CAIDs are equal iff the strings are byte-equal. Cross-suite
equivalence is OUT OF SCOPE (an artifact MAY carry multiple CAIDs, one per
suite it computed). CAID equality is content equality, not semantic
equality: "1.50" and "1.5" are different digests; per-field normalization
guidance lives in the type definition's `digest_notes`, and normalization is
the ISSUER's job. Cross-domain use also requires both sides to pin the same
immutable type definition or registry snapshot; a local name collision is
not interoperability.

## 3. Action types and the registry

- Registered types live in registry/action-types.json, one entry per
  versioned type. Grammar: lowercase dotted segments, final integer version.
- There is NO reserved private-use syntax. The distinction is presence: a
  type is either in a definition source the verifier is configured with
  (the public registry, or a locally pinned definitions file in the SAME schema) or
  it is unknown. Unknown types are a refusal for conforming issuers and a
  policy decision for verifiers (accept-unregistered is a verifier knob,
  default off).
- Versioning: validation semantics are immutable within an active version;
  every field, normalization, or semantic change is a NEW version (`.2`).
- Type entry schema (normative for local definitions too):

```json
{
  "action_type": "payment.release.1",
  "status": "active",
  "risk_class": "irreversible-financial",
  "summary": "Release of a payment instruction to settlement.",
  "required_fields": [
    {"name": "amount", "type": "amount-string",
     "notes": "decimal string, no exponent, no leading '+', no thousands separators"},
    {"name": "currency", "type": "enum", "values_ref": "ISO 4217 alpha-3"},
    {"name": "beneficiary_account", "type": "digest",
     "notes": "sha256:<lowercase hex> of the normalized account identifier; normalization stated by the issuing system of record"},
    {"name": "payment_instruction_id", "type": "string"}
  ],
  "optional_fields": [{"name": "memo", "type": "string"}],
  "digest_notes": "amounts never renormalized after signing; the system of record's form is canonical",
  "references": []
}
```

Field types (closed set v1): `string`, `amount-string`, `digest`
(`sha256:` + lowercase hex), `enum`, `timestamp` (RFC 3339 UTC `Z`),
`integer` (JSON integer, for counts only, never money), `boolean`,
`object`, `array`.

## 4. Computation and verification (closed refusal set)

`computeCaid(actionObject, {suite, definitions})` — conforming issuer:
1. `action_type` present and grammar-valid, else `invalid_action_type`.
2. Type resolvable in definitions, else `unknown_action_type`.
3. Every required field present, else `missing_material_field:<name>`.
4. Every present declared field type-valid, else `mistyped_field:<name>`
   (amount-string violations may refine to `invalid_amount:<name>`).
5. Suite known, else `unknown_suite`.
6. No non-integer number anywhere in the object, else `unsupported_number`.
7. Canonicalize, digest, emit `{caid, digest}`.
Any failure returns `{refusals:[...]}` and NO caid. Fail-closed, never throw
on junk input.

`verifyCaid(actionObject, caidString, {definitions})` — conforming verifier:
1. Strict-parse the string, else `malformed_caid`.
2. In-object `action_type` equals CAID type, else `action_type_mismatch`.
3. Recompute under the CAID's suite; digest equal, else `digest_mismatch`.
4. Run the SAME material validation as compute; a CAID whose object fails
   validation is `invalid_object`, not merely mismatched.
Result: `{valid: bool, reasons: [...]}`. Same inputs, same reasons, same
order, replayable offline by any third party.

## 5. Action-Mapping Profile

Native protocols usually cannot emit the same bytes. A mapping profile is a
relying-party-pinned, hash-identified projection from one exact source media
type, schema, and version into a registered CAID action type. It maps every
target material field using a closed transform set (`copy`, `sha256-utf8`,
or `sha256-jcs`) and declares `no-material-field-loss`. A source artifact
MUST first verify under its native specification and trust anchors; mapping
does not verify signatures, authority, or provenance. The mapping API requires
an affirmative `native_verified` precondition supplied by a trusted adapter;
that signal is never read from presenter-controlled wire content. Missing or
negative native verification produces `INDETERMINATE`.

The v1 profile object, its `source_format`, and each rule are closed shapes.
Unknown members are refused. This prevents a misspelled or future policy
member from being hashed into a profile while the mapper silently ignores it.

Comparison returns exactly one of:

- `EQUIVALENT_UNDER_PROFILE`: both independently verified sources map to the
  same CAID under the exact profiles pinned by the relying party.
- `NOT_EQUIVALENT`: both mappings completed, but the material projections
  differ.
- `INDETERMINATE`: native verification did not succeed, either mapping cannot be completed, the profile is not
  pinned, a source descriptor differs, or any material field is missing.

The result is content correlation only. It never authorizes an action. The
profile author is responsible for identifying every material source field;
that policy assumption is explicit and reviewable rather than inferred by
the mapping engine.

Every successful per-source result carries the source-object digest, pinned
profile digest, projected action, resulting CAID, and suite. A persisted
comparison keeps both per-source results; a bare verdict cannot reproduce
which source objects and profiles produced it.

## 6. What CAID is NOT (goes in every doc, verbatim spirit)

CAID commits an identifier to canonical typed content. It does not
prove the action was authorized, executed, safe, or wise. It confers no
trust, names no humans, and replaces no verifier: every artifact that
carries a CAID still verifies inside its own trust boundary under its own
spec. Composition joins on the identifier; it never ingests another
verifier's evidence into its own trust boundary.

## 7. Security considerations (minimum set for the I-D)

- Digest strength: second-preimage resistance of SHA-256; suite agility is
  the migration path (new suite, not in-place change).
- No domain separation: rationale above; verifiers MUST enforce the
  action_type check; skipping it re-opens cross-context reinterpretation.
- PII: a plain digest keeps a raw identifier out of the object but does not
  make a low-entropy account or patient identifier anonymous. Dictionary
  attack and cross-record correlation remain possible; prefer high-entropy
  opaque references or a documented privacy-preserving commitment scheme.
- Canonicalization malleability: amounts as strings; registry notes; JCS
  and deterministic CBOR are the only permitted forms.
- A CAID is not a capability: possession proves nothing; treat as public.
- The core never infers semantic equality. Mapping profiles provide only
  profile-bounded material equivalence and MUST abstain on loss or ambiguity.
- Type definitions are immutable within a version; cross-domain verifiers
  pin the definition source or registry snapshot.

## 8. Naming note

"CAID" chosen over "CAI" deliberately: CAI collides with the Content
Authenticity Initiative (C2PA's sister org) in the adjacent provenance
space. CAID's known collision (a Chinese advertising identifier) is remote
from this domain. Pronounce "kay-eye-dee" or "kade".

## 9. Package layout (this directory)

- DESIGN.md (this file, normative core)
- README.md (adoption-facing: "the missing join key; works with whatever you already issue")
- ../standards/staged/draft-schrock-canonical-action-identifier-00.xml
- registry/action-types.json, registry/suites.json, registry/GOVERNANCE.md
- impl/js/caid.mjs, impl/python/caid.py, impl/go/caid.go (+ per-impl vector runners)
- conformance/vectors.json and mapping-vectors.json (shared; all impls must agree; vectors carry
  their own INLINE type definitions so conformance never depends on the
  public registry's contents)
- bindings/*.md (one-page grounded composition notes per target spec; PR-ready text, NOT submitted)
- STATUS.md (verified implementation and filing status)

## 10. Publication boundary

The core, registry, implementations, vectors, and draft are intended as open
infrastructure. A binding note is not a claim that the named protocol has
adopted CAID; external submissions and announcements require their own
review and approval.
