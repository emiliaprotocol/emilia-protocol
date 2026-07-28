<!-- SPDX-License-Identifier: Apache-2.0 -->
# Loss Allocation Schedule v1

**Status:** implemented Gate reference artifact with focused tests and a fixed
Ed25519 vector; not an Internet-Draft, standard, contract, insurance policy,
payment instrument, or production-adoption claim

## 1. Scope and claim boundary

`EP-LOSS-ALLOCATION-SCHEDULE-v1` records signed responsibility terms for one
relying party and one exact Reliance Program. Each rule names a failure class,
one responsible party, a currency and maximum minor-unit amount, separately
governed terms, and an optional dispute endpoint.

The signed `claim_boundary` token is
`signed_terms_not_legal_liability_adjudication_enforceability_insurance_coverage_solvency_authorization_or_payment`.
It means:

> This signed artifact records explicit responsibility terms only. It does not
> itself make those terms legally enforceable, prove solvency, provide
> insurance coverage, establish causation or authorization, or move, escrow,
> guarantee, or pay money.

Verification proves only that the closed artifact was signed by the issuer key
pinned by the verifier, that it matches verifier-owned relying-party and
Reliance Program expectations, that a trusted status resolver reported the
exact artifact current and not revoked, and that the artifact is inside its
signed validity interval. Legal applicability and collectibility remain
outside this artifact.

## 2. Closed signed artifact

The artifact uses the shared Reliance Risk Plane JCS/Ed25519 proof:

```json
{
  "@version": "EP-LOSS-ALLOCATION-SCHEDULE-v1",
  "schedule_id": "loss-allocation:payer-program-1",
  "relying_party_id": "payer:example",
  "program": {
    "program_id": "rp.payer.program.1",
    "version": 1,
    "source_digest": "sha256:<64 lowercase hex>",
    "program_digest": "sha256:<64 lowercase hex>"
  },
  "issued_at": "2026-07-28T12:00:00Z",
  "valid_from": "2026-07-28T12:00:00Z",
  "expires_at": "2026-07-29T12:00:00Z",
  "status_target": {
    "type": "loss-allocation-schedule",
    "usage": "reliance"
  },
  "rules": [],
  "claim_boundary": "signed_terms_not_legal_liability_adjudication_enforceability_insurance_coverage_solvency_authorization_or_payment",
  "issuer": {
    "id": "issuer:allocation-committee",
    "key_id": "loss-allocation-key-1"
  },
  "proof": {
    "algorithm": "Ed25519",
    "key_id": "loss-allocation-key-1",
    "body_digest": "sha256:<JCS body digest>",
    "signature_b64u": "<base64url Ed25519 signature>"
  }
}
```

Unknown fields, malformed canonical JSON, invalid timestamps, malformed
identifiers or digests, non-Ed25519 keys, and malformed signatures fail closed.
The artifact does not carry a trusted public key. The verifier resolves
`proof.key_id` through an out-of-band issuer/key pin.

## 3. Rules keyed by failure class

Each rule is a closed object:

```json
{
  "failure_class": "provider_duplicate_effect",
  "responsible_party_id": "provider:example",
  "allocation": {
    "currency": "USD",
    "max_amount_minor": "25000000"
  },
  "terms_digest": "sha256:<digest of separately governed terms>",
  "dispute_endpoint": "https://example.test/disputes"
}
```

- `failure_class` is a schedule-local key. Its presence is not a finding of
  fault or causation.
- `max_amount_minor` is an unsigned decimal string, never a JSON number. It is
  a signed term, not evidence that funds exist or will be paid.
- `terms_digest` binds separately governed explanatory terms without proving
  those terms valid, fair, enforceable, or collectible.
- `dispute_endpoint` is either `null` or an HTTPS URL without credentials. It
  does not prove the endpoint will act.

The same failure class MUST appear exactly once. An identical second rule is
`duplicate_failure_rule`; a second rule with different content is
`conflicting_failure_rule`. Signing and verification refuse both.

## 4. Canonicalization, digests, and signature

The implementation uses the shared hardened Gate canonical JSON primitive:
valid Unicode, plain data objects, dense arrays, safe integers, and
lexicographically sorted object keys.

Let `body` be the complete artifact without `proof`:

```text
proof.body_digest = "sha256:" || hex(SHA-256(JCS(body)))
signature_input   = UTF8("EP-LOSS-ALLOCATION-SCHEDULE-v1" || NUL || JCS(body))
artifact_digest   = "sha256:" || hex(SHA-256(JCS(body + proof)))
```

`lossAllocationScheduleDigest` returns `artifact_digest`.
`lossAllocationRulesDigest` hashes only the artifact version and exact rules;
it deliberately excludes the final Reliance Program digests.

## 5. Verification and status

`verifyLossAllocationSchedule` fails closed across these checks:

1. shared proof shape, body digest, issuer pin, and Ed25519 signature;
2. closed schedule schema and exact claim boundary;
3. a trusted current-status result for the exact `artifact_digest`;
4. signed validity (`valid_from` inclusive, `expires_at` exclusive);
5. verifier-owned relying-party expectation, or issuer/relying-party identity
   equality when no separate expectation is needed; and
6. exact expected Reliance Program ID, version, source digest, and compiled
   program digest.

A status result has `outcome` and `target_digest`. `revoked` returns
`schedule_revoked`; any target other than this artifact returns
`status_target_mismatch`; missing or unavailable status fails closed; and an
expired schedule returns `schedule_stale`.

The `status` option is a trusted verifier input, not presenter evidence. A
deployment MUST obtain it from relying-party-owned code that authenticates the
issuer's current status and prevents rollback. Passing an unauthenticated
presenter-supplied object as `status` would defeat the status check. The signed
artifact alone does not discover global revocation.

## 6. Reliance Program v1 integration without a digest cycle

`lossAllocationScheduleProfileReference` returns a compact artifact pin:

```json
{
  "artifact_type": "EP-LOSS-ALLOCATION-SCHEDULE-v1",
  "artifact_digest": "sha256:<signed artifact digest>",
  "required_status": true
}
```

`createLossAllocationAdmissibilityProfilePin` additionally returns a normal
self-hashed Admissibility Profile and the existing Reliance Program v1 profile
reference fields: `profile_id`, `profile_hash`,
`evaluation_max_age_sec`, and `revocation_required`. No Reliance Program v1
field is added or changed.

The generated profile pins the artifact version, schedule ID, relying-party
ID, issuer ID/key ID, and `lossAllocationRulesDigest`. It deliberately excludes
the Reliance Program `source_digest` and `program_digest`; otherwise inserting
the profile hash into the program would change the program digest that the
schedule is trying to bind.

The construction order is:

1. author schedule identity, issuer, and rules;
2. generate the Admissibility Profile digest pin;
3. compile the unchanged Reliance Program v1 with that profile reference; and
4. place the final source/program digests into the separately signed schedule.

At evaluation time, relying-party-owned code must verify the final schedule
signature, status, program binding, and rules digest. A matching profile hash
alone is not authorization and does not make the terms legally applicable.

## 7. Conformance material

`conformance/vectors/loss-allocation-schedule.v1.json` contains a fixed Ed25519
public key and signed artifact, expected body/artifact/rules/profile digests,
an exact current-status target, and the times used for accepted, stale, and
revoked outcomes. The fixture key is conformance-only and is not a deployment
trust root.
