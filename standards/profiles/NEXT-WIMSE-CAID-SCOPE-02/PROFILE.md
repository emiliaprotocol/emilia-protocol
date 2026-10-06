# WIMSE-CAID-SCOPE-02

## 1. Purpose

`WIMSE-CAID-SCOPE-02` is an experimental companion profile for one narrow
interoperability test. It supersedes this repository's
`WIMSE-CAID-SCOPE-01` review packet (section 8). It maps two operation-family
strings carried in an `agent_delegation` authorization detail to two
versioned CAID action types. It does not change the delegation token, the CAID
format, or either source specification.

The motivating gap is precise. Section 4.1 of
[`draft-asor-wimse-agent-delegation-chain-01`](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-01#section-4.1)
defines a syntactic covering relation for lowercase dotted scopes. On
2026-09-23, Rafael Asor wrote on the public WIMSE list that two deployments
can still assign different meanings to the same verb and both verify a chain
successfully. He said a separate profile or common operation-verb registry
could close that gap and offered to review one. The same message described
possible changes for a future `-02`, including binding covering semantics to
each authorization-detail type and rejecting unsupported types at the
verifier. Those are author-stated revision intentions, not published `-02`
text. This packet continues to evaluate the published `-01` input.

CAID supplies versioned material-action types. The current individual draft,
[`draft-schrock-canonical-action-identifier-05`](https://datatracker.ietf.org/doc/html/draft-schrock-canonical-action-identifier-05),
defines the current identifier as
`canactid:1:<action-type>:<suite>:<digest>` and defines the legacy `caid:`
scheme only for explicit verification of immutable `-04` artifacts. New
issuance and this profile use `canactid:`. They never migrate a signed legacy
identifier by replacing its prefix.

The two type definitions used here are pinned to registry version 5 and the
exact digest of its bytes in `profile.json`. Registry version 5 pins
`payment.release.1.currency` to the SIX ISO 4217 List One snapshot published
2026-09-17. The CAID reference implementation refuses a currency outside that
snapshot as `mistyped_field:currency`. This packet narrows the field further
to a closed `EUR` and `USD` subset. Any other listed ISO 4217 code refuses in
this profile until a new profile version is agreed.

## 2. Layer boundary

The layers remain separate:

1. The native delegation verifier checks the token chain, signatures, parent
   linkage, attenuation, holder binding, time, revocation, scopes, and
   constraints under the Asor profile. This packet does not reimplement those
   checks.
2. This profile maps one covered operation family to one pinned CAID action
   type and verifies that the presented current-scheme CAID commits to a valid
   action object of that exact type.
3. The enforcement point separately decides whether to admit the action under
   local policy and any other required evidence.

`COVERED` in this profile means only: a natively verified leaf delegation
covers the named family, and the supplied action object plus CAID conform to
the pinned type. It does not mean `AUTHORIZED`, `EXECUTED`, safe, legal, or
wise. A family scope can cover many distinct CAIDs; it never substitutes for
the concrete material action.

## 3. Pinned inputs

An implementation of this packet MUST use the exact `profile.json` bytes it
has selected and MUST verify the registry version and SHA-256 digest and the
CAID-05 text digest before evaluation. A change to the authorization-detail
type identifier, operation mapping, CAID type version, identifier scheme,
suite, registry bytes, or evaluation rules requires a new profile version.

The sample pins the `agent_delegation` type used by the published `-01`
delegation draft. Rafael's 2026-09-23 message says the type identifier may
change in a future `-02`. This profile MUST NOT silently follow that change.

The CAID type suffix is not copied into the delegation scope. Under the `-01`
ABNF, each scope segment starts with a lowercase letter, so the numeric final
segment in `payment.release.1` and `tool.call.1` is not a valid scope segment.
The explicit mapping is therefore required.

The `canactid` URI scheme has an IANA provisional registration dated
2026-10-05. The registration supplies a discoverable scheme record; it does
not turn CAID into an RFC, make the status permanent, establish working-group
adoption, or express IETF or IANA endorsement.

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
   an array, return `REFUSED` with `malformed_authorization_detail`.
6. Validate every scope using the published `-01` Section 4.1 grammar. Any
   invalid scope returns `REFUSED` with `malformed_scope` before covering is
   evaluated.
7. `requested_scope` MUST be a valid literal scope and MUST have an exact
   entry in this profile. Otherwise return `REFUSED` with
   `unknown_scope_family`.
8. Apply the published `-01` covering rule. A literal grant covers only an
   identical requested scope. A terminal wildcard covers a requested scope
   only below the same dot-bounded prefix. If no leaf scope covers the
   request, return `REFUSED` with `scope_not_covered`.
9. The action object's `action_type` MUST equal the mapped CAID action type.
   Otherwise return `REFUSED` with `action_type_mismatch`.
10. If `presented_caid` begins with the obsolete `caid:` scheme, return
    `REFUSED` with `legacy_caid_scheme`. Do not rewrite the prefix and do not
    treat a legacy identifier as the current identifier.
11. Before invoking native CAID validation, apply the mapped action type's
    requirements from `profile.json` at
    `action_type_rules.<action_type>.required_profile_fields`. A required
    profile field that is absent, empty, or not a string returns `REFUSED`
    with `invalid_action_object` and the sub-reason
    `missing_or_empty_profile_field:<field>`. Then recompute the CAID under
    the pinned registry, the value-set snapshots it lists, and `jcs-sha256`.
    If native material validation or CAID computation fails, return `REFUSED`
    with `invalid_action_object` and retain the native CAID refusal reasons.
    A profile-pinned external enum failure returns the profile sub-reason
    `external_enum_not_allowed:<field>`.
12. The recomputed `canactid:` identifier MUST byte-equal `presented_caid`.
    Otherwise return `REFUSED` with `caid_mismatch`.
13. Return `COVERED` with `covered`, the mapped action type, and recomputed
    CAID.

All comparisons are case-sensitive. Unknown values are refusals, never a
fallback to local intuition.

## 5. The two mappings

### 5.1 `payment.release` to `payment.release.1`

The family names release of a payment instruction to settlement. The concrete
action MUST include `amount`, `currency`, `beneficiary_account`, and
`payment_instruction_id` exactly as required by the pinned CAID definition.
This packet accepts only `EUR` and `USD` for the currency field, a subset of
the ISO 4217 snapshot the pinned registry requires. A similarly named
operation such as release of a legal hold is not covered.

### 5.2 `tool.call` to `tool.call.1`

The family names invocation of an agent-framework tool. The concrete action
MUST include the stable execution `target`, exact framework `tool` name, and
complete post-default `args` object. Although the pinned CAID registry makes
`occurrence_id` optional in the general type, this profile requires a nonempty
`occurrence_id` for every `tool.call.1` action. The machine-readable source of
that additional requirement is `profile.json` at
`action_type_rules.tool.call.1.required_profile_fields`; it is evaluated
before the general CAID registry, as specified by Rule 11.

A transport retry of the same logical invocation MUST present the identical
action object, including the same `occurrence_id`, and therefore the identical
CAID. A second intended invocation, even with identical arguments, MUST use a
new `occurrence_id` and therefore a new CAID. This correlation rule does not
itself prevent a duplicate effect. Durable single-use admission and provider
idempotency remain enforcement responsibilities outside this profile. A
stateful admission layer MUST refuse reuse of one `occurrence_id` with
different action material, even if each object has a valid CAID.

The CAID registry classifies this type's risk as varying by tool. Mapping a
delegation to it does not make an arbitrary tool safe or authorized.

## 6. Deliberate limits

This packet does not:

- define or claim to implement a future unpublished `-02` delegation draft;
- define multi-detail conjunction, disjunction, or precedence;
- translate native constraints into CAID material fields;
- claim that the EMILIA-maintained CC0 seed registry it pins is an IANA or
  otherwise neutral global action-type registry;
- review or endorse all 62 types of the registry version 5 it pins;
- verify a delegation token, create authority, or make an admission decision;
- prevent replay, duplicate effects, or tool misuse; or
- establish implementation interoperability, deployment, working-group
  adoption, RFC status, permanent URI-scheme registration, or IETF or IANA
  endorsement.

## 7. Source pins

- Rafael Asor, `draft-asor-wimse-agent-delegation-chain-01`, published
  2026-09-03, especially Sections 4.1, 4.3, and 6.
- Rafael Asor, public `wimse@ietf.org` message dated 2026-09-23, Message-ID
  `<CAESAJSUsabSeDKC2yVxtuTPZxoeWwxSN8VWy1tGf6GeMD7kPhg@mail.gmail.com>`.
- Iman Schrock, `draft-schrock-canonical-action-identifier-05`, posted
  2026-10-02, exact text digest pinned in `profile.json`.
- IANA, provisional URI Schemes registration for `canactid`, registered
  2026-10-05 with reference `CAID-05`.
- `caid/registry/action-types.json`, registry version 5, exact SHA-256 pinned
  in `profile.json`, and the value-set files it lists in
  `enum_snapshot_files`.

## 8. Changes from WIMSE-CAID-SCOPE-01

Registry version 5 and CAID-05 change inputs that version 01 pins, and section
3 makes either change require a new profile version. This version:

- pins registry version 5 and the exact checked-in CAID-05 text by digest;
- pins the current `canactid:` scheme and refuses legacy `caid:` without
  rewriting it;
- records the provisional IANA URI-scheme registration with its status and
  claim boundary;
- retains the published delegation draft `-01` as the normative native input
  and labels the delegation author's possible `-02` changes as unpublished
  intentions; and
- deterministically derives its vector suite from the version 01 corpus and
  adds an explicit legacy-scheme refusal.

The mappings, authorization-detail type, operation-family covering rules,
currency subset, tool-call occurrence rule, and result vocabulary are
otherwise unchanged.
