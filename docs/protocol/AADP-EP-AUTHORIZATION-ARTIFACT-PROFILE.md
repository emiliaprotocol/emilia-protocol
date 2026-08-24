<!-- SPDX-License-Identifier: Apache-2.0 -->
# Authorization-artifact digest profile for AADP and EP

Status: implementation-backed candidate composition profile. Not an AADP
revision, IETF working-group result, joint publication, or authorization
decision.

## 1. Purpose

AADP defines a local decision, approval, permit, enforcement, and report
lifecycle. EP Authorization Bundles carry portable approval evidence for an
exact action. This profile joins the two by digest without making either core
protocol depend on the other.

The profile defines an optional `authorization_artifact` object for an AADP
approval record and its durable evidence entry. Artifact delivery is
profile-specific and outside this document. A deployment MAY also return the
object as an optional Decide Response extension when the same object has been
persisted in the authoritative evidence record.

## 2. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be
interpreted as described in BCP 14 when, and only when, they appear in all
capitals.

## 3. Profile-neutral object

```json
{
  "profile": "AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_profile": "EP-AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_digest": "sha256:6d8a602f3a58a00c3436304d33d0d5732433ef302b30643b079cc3524f8b7dbf",
  "verification_outcome": "verified",
  "action_mapping_profile": "https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1",
  "action_digest": "sha256:a84820a5cd672208628c7917ca50b7819a0d2654d8102a15d471850af09e74a3"
}
```

The object is closed. Unknown or missing members are malformed.

- `profile` MUST equal `AADP-AUTHORIZATION-ARTIFACT-v1`.
- `artifact_profile` selects the native artifact-verification profile.
- `artifact_digest` is SHA-256 over the exact canonical artifact, or the exact
  artifact reference the PDP could not reach.
- `verification_outcome` distinguishes `verified`, `not_satisfying`, and
  `not_reachable`. The latter two have different remedies and MUST NOT be
  collapsed.
- `action_mapping_profile` is an absolute identifier for the
  relying-party-pinned mapping from the AADP action to the artifact's action
  model.
- `action_digest` is SHA-256 over AADP's own canonical action identity. It is
  not a foreign artifact action digest.

The JSON Schema is
`conformance/schemas/aadp-authorization-artifact.v1.schema.json`.

## 4. Processing

An AADP PDP implementing this profile:

1. MUST obtain the external artifact through the selected profile's native
   delivery mechanism.
2. MUST natively verify that artifact under locally pinned trust and policy.
3. MUST derive the expected action from the AADP `action_type` and `params`
   using a locally pinned mapping profile.
4. MUST verify that the native artifact binds that exact mapped action.
5. MUST record whether native verification succeeded, found a reachable but
   non-satisfying artifact, or could not reach the artifact or a required
   verification dependency.
6. MUST derive the profile-neutral object above and persist it in the approval
   and evidence record.
7. MUST compare any presenter-supplied projection with the independently
   derived object by exact canonical bytes.
8. MUST continue the ordinary AADP approval, re-evaluation, permit,
   obligation, adapter, and report lifecycle.

Malformed artifacts, failed native verification, action mismatch, profile
substitution, and digest mismatch record `not_satisfying` and are hard
refusals. An unavailable native artifact, verifier, trust source, current
policy result, or action mapping is recorded as `not_reachable`, is
indeterminate, and MUST NOT be converted into a permit.

## 5. EP Authorization Bundle profile

For `EP-AADP-AUTHORIZATION-ARTIFACT-v1`, the external artifact is an
`EP-AUTHORIZATION-BUNDLE-v1` as specified by EP Authorization Receipts. The PDP
MUST call the native EP verifier with:

- the exact mapped action as `expectedAction`;
- a locally pinned audience;
- locally pinned approver keys and accepted key classes;
- the locally selected approver set;
- a fresh authorization instance;
- current local policy;
- any native authorization binding required by the deployment; and
- current status when required by local policy.

Only the EP `SATISFIED` evidence verdict produces the neutral hook. EP
`REFUSE` remains refusal. EP `INDETERMINATE` remains indeterminate. The EP
verdict is evidence satisfaction, not the AADP authorization decision.

## 6. Non-authority rule

The authorization-artifact object MUST NOT be used as:

- an AADP `approval_ref`;
- an AADP `permit_id`;
- an AADP obligation;
- a provider idempotency key;
- a substitute for AADP policy re-evaluation;
- a reason to bypass a kill switch or current refusal; or
- proof of exactly-once physical execution.

A valid EP artifact can support an AADP approval record. It cannot issue an
AADP permit by itself. AADP approval remains single-use. A timeout or unknown
provider outcome is reported through AADP and does not reopen the approval for
blind retry.

## 7. Implementation and evidence

The reference module is
`packages/verify/src/aadp-authorization-artifact.ts`. The source-pinned runner
is `conformance/composition/aadp-ep-authorization-v0.1`. Fourteen positive,
hostile, unavailable, lifecycle, and separation cases pass with deterministic
report digest
`sha256:49af4e8fe20ea2ba96ca2ccd7697d368f9c5161cb3777a788b5aef166ac6e7b2`.

The runner executes the EMILIA verifier and a bounded AADP -01 lifecycle model.
It does not execute onedoor and is not an independent AADP implementation.

## 8. Joint-publication path

If the AADP author agrees, the next document can be a jointly maintained
composition profile. That document should normatively reference:

- `draft-saha-aadp` for AADP decision, approval, permit, and report semantics;
- `draft-schrock-ep-authorization-receipts` for EP Authorization Bundle
  verification and evidence semantics; and
- BCP 14 and the selected canonical JSON and digest specifications.

AADP itself can mention this working profile and implementation informatively.
EP can do the same. Neither core document needs to make the other a normative
dependency.

## 9. Normative references

- Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119.
- Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174.
- Saha, S., "Agentic Action Decision Protocol (AADP)",
  `draft-saha-aadp-01`.
- Schrock, I., "Authorization Receipts for AI Agent Actions",
  `draft-schrock-ep-authorization-receipts-12`.

## 10. Informative references

- EMILIA Protocol, "AADP and EP authorization-artifact composition v0.1",
  source-pinned executable profile and report.
- Saha, S., "onedoor", AADP reference implementation. The pinned revision was
  inspected for alignment but not executed by this profile runner.
