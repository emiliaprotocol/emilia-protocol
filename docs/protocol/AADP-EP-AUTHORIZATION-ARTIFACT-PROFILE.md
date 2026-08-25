<!-- SPDX-License-Identifier: Apache-2.0 -->
# Authorization-artifact digest profile for AADP and EP

Status: EMILIA-authored, implementation-backed candidate composition profile.
It is not an AADP revision, joint publication, implementation-independence
result, adoption statement, or authorization decision.

## 1. Purpose

The Agent Action Decision Protocol (AADP) defines a local decision, approval,
permit, enforcement, and report lifecycle. EP Authorization Bundles carry
portable approval evidence for an exact action. This profile records a
digest-bound projection of native EP verification in an AADP approval and
evidence record without making either core protocol depend on the other.

Artifact acquisition and storage are deployment-specific. A deployment that
exposes this object on a wire does so as an extension profile; the object is
not part of the AADP -01 core message schema.

## 2. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be
interpreted as described in BCP 14 when, and only when, they appear in all
capitals.

## 3. Closed evidence object

```json
{
  "profile": "AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_profile": "EP-AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_digest": "sha256:...",
  "native_verification": "VERIFIED",
  "evidence_satisfaction": "SATISFIED",
  "verification_record_digest": "sha256:...",
  "action_mapping": {
    "profile": "AADP-ACTION-MAPPING-RECORD-v1",
    "mapping_profile": "https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1",
    "implementation": {
      "id": "urn:emilia:repository-source:aadp-authorization-artifact",
      "version": "source-lock-v1",
      "digest": "sha256:..."
    },
    "resolver": {
      "id": "urn:emilia:mapping-resolver:closed-json-v1",
      "version": "1.0.0",
      "digest": "sha256:...",
      "configuration_digest": "sha256:..."
    },
    "source_action_digest": "sha256:...",
    "mapped_action_digest": "sha256:...",
    "no_material_field_loss": true
  }
}
```

The object is closed. Unknown or missing members are malformed.

The reference profile identifies the checked-in, source-locked implementation.
It does not assert that the AADP subpath exists in any already-published npm
version. A future package release must use a new package version and separately
verify the exact registry tarball before a `pkg:npm` identifier replaces this
repository-source identifier.

The repository source lock binds each checked-in runtime path to its exact
SHA-256 bytes. It intentionally makes no immutable revision claim from inside
the same change that introduces those files.

- `artifact_digest` binds the exact canonical native artifact.
- `native_verification` records whether the native verifier returned
  `VERIFIED`, `REFUSED`, or `UNAVAILABLE`.
- `evidence_satisfaction` separately records the EP result: `SATISFIED`,
  `REFUSE`, or `INDETERMINATE`.
- `verification_record_digest` binds the complete record described in
  Section 5.
- `action_mapping` binds the relying-party-selected mapping configuration and
  both action digests.

The JSON Schema is
`conformance/schemas/aadp-authorization-artifact.v1.schema.json`.

## 4. Loss-aware action mapping

The PDP MUST select a closed mapping configuration locally. The configuration
MUST identify the source action type, mapped action type, implementation,
resolver, and every material source parameter.

Before native artifact verification, the implementation MUST:

1. refuse an action type the profile does not declare;
2. refuse any missing or unknown material parameter;
3. reject reserved, duplicate, or parent/child-conflicting target paths;
4. map each declared source parameter to exactly one declared target path with
   the pinned deterministic resolver;
5. compare the canonical bytes at each source and target location;
6. refuse a missing, changed, duplicated, or dropped value; and
7. bind the source action, mapped action, mapping implementation, resolver
   implementation, and complete resolver configuration in the output record.

This profile does not infer that an unknown field is immaterial. An unknown
`debit_account` therefore refuses instead of disappearing into a lossy
payment mapping.

## 5. Complete native verification record

The record digest MUST cover:

- native artifact profile and artifact digest;
- native verification outcome;
- EP evidence-satisfaction outcome;
- verifier implementation identity, version, and digest;
- complete serializable trust-configuration digest;
- evaluation-time, current-status, and current-policy digest;
- source and mapped action digests; and
- the complete native verifier result digest, including checks and reasons.

This version does not accept opaque verifier callbacks without a separately
pinned extension description. An unbound callback refuses before it can
produce a record whose digest silently omits security-relevant code.

## 6. EP Authorization Bundle profile

For `EP-AADP-AUTHORIZATION-ARTIFACT-v1`, the native artifact is an
`EP-AUTHORIZATION-BUNDLE-v1`. The PDP supplies:

- the exact mapped action as `expectedAction`;
- a locally pinned audience;
- locally pinned approver keys and accepted key classes;
- the locally selected approver set;
- a fresh authorization instance;
- current local policy;
- any required native authorization binding; and
- current status when required by local policy.

Native `VERIFIED` and EP `SATISFIED` are separate fields. Neither is an AADP
authorization decision. The helper always returns
`authorization_decision: false`.

## 7. AADP processing and precedence

The bounded AADP model follows the draft's order:

1. Evaluate the AADP kill switch first.
2. Apply current local AADP policy.
3. If the composition profile is required, independently derive the expected
   artifact record and compare any presenter projection by canonical bytes.
4. Re-evaluate the ordinary AADP approval state.
5. Only then issue an AADP `permit` and consume the approval.

The kill switch MUST win without reading malformed, unavailable, or stale EP
inputs. A reachable, definite profile failure maps to an AADP `deny` with a
vendor reason. An unavailable verification dependency produces no AADP wire
response; the PEP follows AADP failure semantics. AADP -01 does not define an
`indeterminate` verdict, and this profile MUST NOT invent one.

A malformed AADP request is different from an unavailable internal
dependency. It produces the draft-required `deny` with reason `malformed`
without evaluating the EP hook.

## 8. Non-authority rule

The authorization-artifact object MUST NOT be used as:

- an AADP `approval_ref`;
- an AADP `permit_id`;
- an AADP obligation;
- a provider idempotency key;
- a substitute for AADP policy re-evaluation;
- a reason to bypass the AADP kill switch or current refusal; or
- proof of exactly-once physical execution.

A valid EP artifact may be required evidence for an AADP decision. It cannot
issue an AADP permit by itself. AADP approval remains single-use. A timeout or
unknown provider outcome does not reopen approval for blind retry.

## 9. Implementation and evidence

The reference module is
`packages/verify/src/aadp-authorization-artifact.ts`. The source-pinned runner
is `conformance/composition/aadp-ep-authorization-v0.1`. It executes 22
positive, hostile, unavailable, lifecycle, material-field, and separation
cases and produces a deterministic report.

The source verifier hashes the actual fetched bytes of:

- `draft-saha-aadp-01`;
- three inspected onedoor files at the pinned commit; and
- the declared local EP artifact, verifier-version, verifier-source, and
  mapping inputs.

The report embeds the complete source lock, so its report digest covers every
declared hash.

## 10. Source and claim boundary

The AADP request fixtures are valid AADP -01 JSON projections using Sections
5.1, 5.2, and 5.3. The AADP lifecycle is a bounded draft-derived model. The
runner does not execute onedoor.

The evidence is same-team implementation evidence. It is not an independent
AADP implementation, an interoperability result, AADP adoption, IETF
working-group action, joint publication, or endorsement.

## 11. References

- Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119.
- Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174.
- Saha, S., "The Agent Action Decision Protocol (AADP): Per-Action
  Authorization for AI Agents", `draft-saha-aadp-01`.
- Schrock, I., "Authorization Receipts for AI Agent Actions",
  `draft-schrock-ep-authorization-receipts-12`.
