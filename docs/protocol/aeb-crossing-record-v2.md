# EP-AEB-CROSSING-RECORD-v2

`EP-AEB-CROSSING-RECORD-v2` is an evidence record for a completed boundary
evaluation. It does not grant authority and must not be used to admit a later
action.

Version 2 adds one guarantee to the frozen v1 format: the record carries a
recomputable commitment to the complete admission domain. The commitment is
the `EP-AEB-CROSSING-RECORD-v2:admission-domain` typed digest of these exact
members:

- `relying_party_id`
- `audience`
- `executor_id`
- `state_domain_id`

The v2 contract digest commits that admission-domain digest together with the
exact action, native-authority projection, requirement profile, and authority
validity. A verifier recomputes both digests from the signed body. Unknown or
missing domain members, a changed action or authority context, and stale
authority presented as admitted all fail closed.

## Issuance

Use `issueAebCrossingRecordV2`. The caller must supply the evaluated action and
admission domain separately from the record draft. Issuance compares both
values with the draft before calling a signing operation. This API boundary is
intentional: a generic issuer cannot infer an opaque native adapter's context.

The signing input starts with the distinct
`EP-AEB-CROSSING-RECORD-v2\0` domain. V1 and v2 signatures are therefore not
interchangeable.

## Verification and migration

Use the verifier that matches the declared version:
`verifyAebCrossingRecord` for v1 and `verifyAebCrossingRecordV2` for v2. Neither
verifier accepts the other version, including a record whose version label was
changed without reissuance.

Issue v2 for new integrations that need recomputable admission-domain binding.
Continue verifying existing v1 records under v1 rules. A v1 record remains v1
evidence and does not acquire the v2 guarantee through relabeling, wrapping, or
documentation.

V1 has no scheduled retirement date. Any future retirement requires a separate
published policy with an effective date, relying-party migration window, and
an archival-verification rule. Retirement must not invalidate historical v1
signatures or reinterpret their contract digest.

## Separate lifecycle index

`EP-AEB-CROSSING-LIFECYCLE-INDEX-v2` is a different, domain-separated
artifact. It does not replace this profile, and the two version strings are not
interchangeable.

The lifecycle index exists to avoid turning a crossing record into a second
flattened authority model. It contains the action and a recomputable admission
domain digest, then references the independently verifiable records for:

- evidence evaluation;
- local admission;
- authority reservation or consumption;
- provider entry;
- effect observation;
- provider outcome; and
- reconciliation.

It deliberately contains no `native_authority`, no copied native or AuthZEN
decision, no referee verdict, and no raw admission-domain fields. A valid index
is evidence that its signer committed to those references. It is not authority
to execute, and every referenced record still has to verify under its own
profile and relying-party pins.

`upgradeAebCrossingRecordV1ToLifecycleIndexV2` first verifies the source under
caller-pinned v1 keys, then preserves its resolvable references. If a v1 axis
asserted a later provider state but v1 carried no digest for the underlying
record, the conversion is signed as
`INDETERMINATE` with a specific reason. It never manufactures the missing
outcome, observation, or reconciliation evidence.
