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

## Evaluation binding

Both record versions carry `lifecycle_records.evaluation_digest`, and the
lifecycle index below carries `lifecycle.evaluation`. A signature over that
digest shows only that the signer committed to it. It does not show that the
cited evaluation concerned this operation, action, or native authority.

The evaluation reference is the untyped `digestAeb` over the complete signed
`AEB-EVALUATION-v1` or `AEB-EVALUATION-v2` record. That is the
`record_digest` returned by `verifyAebEvaluation` and `verifyAebEvaluationV2`.
It is not `aebEvaluationV2Digest`, which is a typed digest over the unsigned v2
body. `aebCrossingEvaluationReference(evaluation)` returns the reference
(`{ profile, digest }`) an issuer should commit to.

`verifyAebCrossingRecord`, `verifyAebCrossingRecordV2`, and
`verifyAebCrossingLifecycleIndexV2` accept an optional `evaluation` record.
When it is supplied, the verifier refuses unless all of these hold:

- the recomputed reference digest equals the committed digest
  (`evaluation_digest_mismatch`);
- for an index that carries a profile label, the record's `@type` equals it
  (`evaluation_profile_mismatch`). The label is bound because the digested
  bytes contain `@type`;
- the operation identifier and CAID are the record's
  (`evaluation_operation_mismatch`, `evaluation_action_mismatch`);
- if the evaluation committed to a normalized action or is SATISFIED, that
  action is the record's action (`evaluation_action_mismatch`);
- for a crossing record, one evaluated leg has the native authority's
  `evidence_digest`, is not weaker than the record's native verification and
  acceptance, and mapped exactly this action when the record claims
  `EXACT_MATCH` (`evaluation_authority_unmatched`,
  `evaluation_authority_inconsistent`). Replay units and adapter identifiers
  are derived under different profiles on each side and are not join keys;
- an `ADMIT` crossing record cites a SATISFIED evaluation
  (`evaluation_verdict_inconsistent`) in which the native authority's own leg
  is SATISFIED (`evaluation_authority_inconsistent`).

A malformed evaluation input refuses with `evaluation_malformed`; the
verifier does not throw. The result reports `evaluation_binding`:

- `BOUND` when the supplied evaluation passed the join;
- `INDETERMINATE` when no evaluation was supplied (or the record was refused
  before the join). The evaluation digest is then an unverified pointer; and
- `MISMATCH` when the supplied evaluation failed the join. The record is
  refused.

`BOUND` does not verify the evaluation's own signature or re-derivation. The
evaluation still has to verify under its own verifier and relying-party pins.

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

The verifier needs `expected_evaluation` (a caller-pinned reference),
`evaluation` (the record itself), or both. A pointer alone cannot establish
the join, so the result then reports `evaluation_binding: "INDETERMINATE"`.
Supplying neither refuses with `evaluation_reference_required`.

The index enforces lifecycle order. Nothing may follow a missing local
admission reference. Provider entry, and therefore any effect observation,
provider outcome, or reconciliation, requires an authority custody reference
in phase `RESERVATION` or `CONSUMPTION`. Only a conversion reporting
`INDETERMINATE` may carry a legacy provider entry whose custody it could not
resolve. A `COMPLETE` conversion requires a labeled evaluation reference and
resolved custody.

`upgradeAebCrossingRecordV1ToLifecycleIndexV2` first verifies the source under
caller-pinned v1 keys, then preserves its resolvable references. V1 never
labeled its evaluation digest. Unless the caller passes the source evaluation
as `source_evaluation` and it binds to the source record, the index carries the
digest with `profile: null` and the conversion is `INDETERMINATE` with
`evaluation_reference_unverified`. A supplied evaluation that does not bind is
refused with `source_evaluation_mismatch` and nothing is signed.

If a v1 axis asserted a later provider state but v1 carried no digest for the
underlying record, the conversion is signed as `INDETERMINATE` with a specific
reason. It never manufactures the missing outcome, observation, or
reconciliation evidence. V1 also never enforced lifecycle order. A custody or
provider-entry reference recorded without a local admission reference, a
provider entry without a custody reference, and a provider entry on a record
that did not admit are reported `INDETERMINATE`
(`custody_reference_without_admission`,
`provider_entry_reference_without_admission`,
`provider_entry_without_custody_reference`, `provider_entry_without_admit`).
Such a verified v1 record converts; it does not fail with
`lifecycle_order_invalid`.
