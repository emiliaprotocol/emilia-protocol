# WIMSE-CAID-SCOPE-01

## 1. Purpose

`WIMSE-CAID-SCOPE-01` is an experimental companion profile for one narrow
interoperability test. It supersedes `WIMSE-CAID-SCOPE-00` (section 8). It
maps two operation-family strings carried in an
`agent_delegation` authorization detail to two versioned CAID action types.
It does not change the delegation token, the CAID format, or either source
specification.

The motivating gap is precise. Section 4.1 of
[`draft-asor-wimse-agent-delegation-chain-01`](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-01#section-4.1)
defines a syntactic covering relation for lowercase dotted scopes. On
2026-09-23, Rafael Asor wrote on the public WIMSE list that two deployments
can still assign different meanings to the same verb and both verify a chain
successfully. He said a separate profile or common operation-verb registry
could close that gap and offered to review one. The same message said the
planned `-02` would bind covering semantics to each authorization-detail type,
reject an unsupported type at the verifier, and would not itself supply the
common vocabulary. Those are stated revision intentions, not published `-02`
text.

CAID supplies versioned material-action types. The current individual draft,
[`draft-schrock-canonical-action-identifier-02`](https://datatracker.ietf.org/doc/html/draft-schrock-canonical-action-identifier-02),
defines `payment.release.1` and `tool.call.1`. The definitions used here are
pinned to registry version 4 and the exact `action-types.json` digest in
`profile.json`.

Registry version 4 pins `payment.release.1.currency` to the SIX ISO 4217 List
One snapshot published 2026-09-17, a local value-set file whose values digest
and whole-file digest the registry records. The CAID reference implementation
refuses a currency outside that snapshot as `mistyped_field:currency`. This
packet narrows the field further to a closed `EUR` and `USD` subset of that
snapshot. Any other listed ISO 4217 code refuses in this profile until a new
profile version is agreed.

## 2. Layer boundary

The layers remain separate:

1. The native delegation verifier checks the token chain, signatures,
   parent linkage, attenuation, holder binding, time, revocation, scopes, and
   constraints under the Asor profile. This packet does not reimplement those
   checks.
2. This profile maps one covered operation family to one pinned CAID action
   type and verifies that the presented CAID commits to a valid action object
   of that exact type.
3. The enforcement point separately decides whether to admit the action under
   local policy and any other required evidence.

`COVERED` in this profile means only: a natively verified leaf delegation
covers the named family, and the supplied action object plus CAID conform to
the pinned type. It does not mean `AUTHORIZED`, `EXECUTED`, safe, legal, or
wise. A family scope can cover many distinct CAIDs; it never substitutes for
the concrete material action.

## 3. Pinned inputs

An implementation of this packet MUST use the exact `profile.json` bytes it
has selected and MUST verify the registry version and SHA-256 digest before
evaluation. A change to the authorization-detail type identifier, operation
mapping, CAID type version, suite, registry bytes, or evaluation rules requires
a new profile version.

The sample pins the `agent_delegation` type used by the published `-01` draft.
Rafael's 2026-09-23 message says the `-02` type identifier may change to a URI.
This profile MUST NOT silently follow that change.

The CAID type suffix is not copied into the delegation scope. Under the `-01`
ABNF, each scope segment starts with a lowercase letter, so the numeric final
segment in `payment.release.1` and `tool.call.1` is not a valid scope segment.
The explicit mapping is therefore required.

## 4. Deterministic evaluation

Evaluation takes these trusted-adapter inputs:

- `native_chain_verified`: whether the complete native delegation chain
  passed its own verifier;
- `constraints_satisfied`: whether the attempted action satisfied every
  applicable native constraint;
- `authorization_details`: the leaf token's complete array;
- `requested_scope`: one literal operation family for the attempted action;
- `action_object`: the complete CAID action object; and
- `presented_caid`: the CAID supplied for that object.

The first failing rule determines the result:

1. If `native_chain_verified` is not exactly `true`, return `REFUSED` with
   `native_chain_unverified`.
2. If `constraints_satisfied` is not exactly `true`, return `REFUSED` with
   `constraints_not_satisfied`.
3. If `authorization_details` does not contain exactly one object, return
   `REFUSED` with `unsupported_authorization_details_cardinality`. This
   version defines no multi-detail composition rule and never reads only the
   first entry.
4. If that object's `type` is not the exact pinned type, return `REFUSED` with
   `unknown_authorization_details_type`.
5. If the object has a member other than `type`, `scopes`, or `constraints`,
   if `scopes` is not an array, or if a present `constraints` member is not
   an array, return `REFUSED` with
   `malformed_authorization_detail`.
6. Validate every scope using the `-01` Section 4.1 grammar. Any invalid scope
   returns `REFUSED` with `malformed_scope` before covering is evaluated.
7. `requested_scope` MUST be a valid literal scope and MUST have an exact
   entry in this profile. Otherwise return `REFUSED` with
   `unknown_scope_family`.
8. Apply the `-01` covering rule. A literal grant covers only an identical
   requested scope. A terminal wildcard covers a requested scope only below
   the same dot-bounded prefix. If no leaf scope covers the request, return
   `REFUSED` with `scope_not_covered`.
9. The action object's `action_type` MUST equal the mapped CAID action type.
   Otherwise return `REFUSED` with `action_type_mismatch`.
10. Before invoking native CAID validation, apply the mapped action type's
    requirements from `profile.json` at
    `action_type_rules.<action_type>.required_profile_fields`. A required
    profile field that is absent, empty, or not a string returns `REFUSED`
    with `invalid_action_object` and the sub-reason
    `missing_or_empty_profile_field:<field>`. Then recompute the CAID under
    the pinned registry, the value-set snapshots it lists, and `jcs-sha256`.
    If native material validation or
    CAID computation fails, return `REFUSED` with `invalid_action_object` and
    retain the native CAID refusal reasons. A profile-pinned external enum
    failure returns the profile sub-reason
    `external_enum_not_allowed:<field>`.
11. The recomputed CAID MUST byte-equal `presented_caid`. Otherwise return
    `REFUSED` with `caid_mismatch`.
12. Return `COVERED` with `covered`, the mapped action type, and recomputed
    CAID.

All comparisons are case-sensitive. Unknown values are refusals, never a
fallback to local intuition.

## 5. The two mappings

### 5.1 `payment.release` to `payment.release.1`

The family names release of a payment instruction to settlement. The
concrete action MUST include `amount`, `currency`, `beneficiary_account`, and
`payment_instruction_id` exactly as required by the pinned CAID definition.
This packet accepts only `EUR` and `USD` for the currency field, a subset of
the ISO 4217 snapshot the pinned registry requires. A similarly named operation such as release of a legal hold
is not covered.

### 5.2 `tool.call` to `tool.call.1`

The family names invocation of an agent-framework tool. The concrete action
MUST include the stable execution `target`, exact framework `tool` name, and
complete post-default `args` object. Although the pinned CAID registry makes
`occurrence_id` optional in the general type, this profile requires a nonempty
`occurrence_id` for every `tool.call.1` action. The machine-readable source of
that additional requirement is `profile.json` at
`action_type_rules.tool.call.1.required_profile_fields`; it is evaluated
before the general CAID registry, as specified by Rule 10.

A transport retry of the same logical invocation MUST present the identical
action object, including the same `occurrence_id`, and therefore the identical
CAID. A second intended invocation, even with identical arguments, MUST use a
new `occurrence_id` and therefore a new CAID. This correlation rule does not
itself prevent a duplicate effect. Durable single-use admission and provider
idempotency remain enforcement responsibilities outside this profile. In
particular, a stateful admission layer MUST refuse reuse of one `occurrence_id`
with different action material, even if each object has a valid CAID.

The CAID registry classifies this type's risk as varying by tool. Mapping a
delegation to it does not make an arbitrary tool safe or authorized.

## 6. Deliberate limits

This packet does not:

- define the future `-02` authorization-detail type identifier;
- define multi-detail conjunction, disjunction, or precedence;
- translate native constraints into CAID material fields;
- claim that the current EMILIA-maintained CC0 seed registry is an IANA or
  otherwise neutral global registry;
- review or endorse all 52 types in that registry;
- verify a delegation token, create authority, or make an admission decision;
  or
- establish implementation interoperability, deployment, working-group
  adoption, RFC status, or IETF endorsement.

## 7. Source pins

- Rafael Asor, `draft-asor-wimse-agent-delegation-chain-01`, published
  2026-09-03, especially Sections 4.1, 4.3, and 6.
- Rafael Asor, public `wimse@ietf.org` message dated 2026-09-23, Message-ID
  `<CAESAJSUsabSeDKC2yVxtuTPZxoeWwxSN8VWy1tGf6GeMD7kPhg@mail.gmail.com>`.
- Iman Schrock, `draft-schrock-canonical-action-identifier-02`, published
  2026-08-06, especially Sections 4, 5, and 8.
- `caid/registry/action-types.json`, registry version 4, exact SHA-256 pinned
  in `profile.json`, and the ISO 4217 value-set file it lists in
  `enum_snapshot_files` (values digest `values_sha256` and whole-file digest
  `snapshot_sha256`).

## 8. Changes from WIMSE-CAID-SCOPE-00

Registry version 4 changed the registry bytes that `-00` pins, and section 3
makes any change to those bytes a new profile version. `-00` therefore refuses
to evaluate against the current registry, which is the behavior section 3
requires. This version:

- pins registry version 4 by digest and loads the value-set snapshot it lists;
- records the ISO 4217 snapshot label and digest beside the `EUR` and `USD`
  subset, and requires the subset to lie inside that snapshot;
- expects `mistyped_field:currency` from CAID validation for a currency outside
  the snapshot (vector `currency-outside-pinned-snapshot-refused`, formerly
  `unverified-external-currency-refused`); and
- adds `iso-currency-outside-profile-subset-refused`, where a listed ISO 4217
  code outside the profile subset refuses as
  `external_enum_not_allowed:currency`.

The mappings, the authorization-detail type, and every other evaluation rule
are unchanged.
