# Incident Action Authorization Field Group

Version: `0.1`

Status: draft, unsubmitted proposal

Date: 2026-08-16

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used in
their ordinary standards sense.

## Page 1: unit, fields, and codes

### 1. Purpose

This field group records what authority applied immediately before one
AI-agent action was attempted and how inspectable the evidence for that coding
is. It is designed for incident interchange and retrospective analysis. It
adds an authorization axis without replacing an incident database's fields for
harm, cause, severity, intent, lifecycle stage, or response.

The coding unit is one materially distinct action that produced, attempted, or
would have produced an external side effect. A privileged read MAY be a coding
unit when the read is material to the incident. Multiple actions MUST be split
when their authorization status, execution result, or evidence differs.

### 2. Required field group

| Field | Cardinality | Meaning |
|---|---:|---|
| `spec_version` | 1 | Fixed to `aiuc-incident-fields-v0.1` for this draft. |
| `incident_ref` | 1 | External incident namespace, identifier, and canonical URL. |
| `action_ref` | 1 | Stable identifier for this action within the incident. |
| `action_summary` | 1 | Neutral description of the attempted side effect. |
| `action_class` | 1 | Separate side-effect class, using the Chen-aligned list below. |
| `authorization.status` | 1 | Authorization state immediately before first attempt. |
| `authorization.basis_summary` | 1 | The mandate, approval, denial, revocation, or scope boundary used to code the state. |
| `authorization.decision_timing` | 1 | Whether the evidenced decision preceded the attempt. |
| `authorization.evidence_grade` | 1 | Evidence grade for the authorization coding, not for the whole incident. |
| `authorization.evidence_refs` | 1..n | Identifiers of source entries supporting the code. |
| `execution.status` | 1 | Observed action result, kept separate from authorization. |
| `execution.evidence_grade` | 1 | Evidence grade for the result. |
| `execution.evidence_refs` | 1..n | Identifiers of source entries supporting the result. |
| `sources` | 1..n | URLs and source roles referenced by the coding. |
| `coding_limitations` | 1..n | Material uncertainty or unavailable evidence. |

### 3. `authorization.status`

Coders MUST apply the first definition fully supported by evidence. Silence is
not evidence that authority existed or was absent.

| Code | Coding test |
|---|---|
| `standing_authority` | A documented mandate or policy was active before the attempt and covered this action class, target, parameters, and time. No action-specific approval was required by that mandate. |
| `specific_approval` | An authorized principal approved this exact action, or a bounded bundle containing it, before the attempt. A generic instruction to pursue a goal is insufficient. |
| `denied` | Approval for this action or bounded bundle was sought and expressly refused before the attempt. Use only when the evidence shows a refusal, not mere lack of approval. |
| `revoked` | Authority that previously covered the action was withdrawn, frozen, expired, or otherwise made inactive before the attempt. The evidence MUST show the withdrawal or expiry. |
| `outside_scope` | A documented active mandate existed, but this action's class, target, parameters, or time fell outside it. Use only when both the mandate boundary and mismatch are evidenced. |
| `authority_absent` | Evidence positively establishes that no active mandate or action-specific approval governed the action before the attempt. Failure to locate an approval is insufficient; use `indeterminate` unless absence itself is evidenced. |
| `indeterminate` | Available evidence is missing, conflicting, or too coarse to establish any other code. This is the required default under uncertainty. |

`authorization.decision_timing` is `before_attempt`, `after_attempt`, or
`indeterminate`. An approval or ratification first evidenced after execution
MUST NOT be backdated; the pre-attempt status remains `indeterminate`,
`denied`, `revoked`, or `outside_scope` as supported.

### 4. `action_class`

This is an orthogonal compatibility axis based on the seven-class taxonomy in
Chen, arXiv:2605.25632, Section 3.1:

`read_only`, `additive_write`, `modify_write`, `destructive`, `monetary_low`,
`monetary_high`, or `external_commit`.

The classes describe the side effect, not whether a human or organization
authorized it. Implementers SHOULD use Chen's priority rules when predicates
overlap. A destructive action can therefore be specifically approved, revoked,
denied, outside scope, or indeterminate. Importing these labels does not import
Chen's actuarial runtime, reserve model, or safe-default policy.

## Page 2: evidence, outcome, validation, and limits

### 5. Evidence grades

Evidence grade describes inspectability and provenance. It is not a confidence
score, legal finding, truth guarantee, or statement that a recipient accepted
the evidence.

| Code | Minimum evidence |
|---|---|
| `E0_no_reviewable_evidence` | No cited artifact lets a reviewer assess the coded fact. This grade normally requires `indeterminate`. |
| `E1_party_attested` | A named involved party publicly attests the fact or publishes a screenshot, transcript, or record, but an independent reviewer cannot validate the material binding from the artifact alone. |
| `E2_independently_correlated` | A source independent of the evidence producer records the material fact and correlates it with at least one identifiable involved-party statement or contemporaneous record. Repetition of the same anonymous claim is insufficient. |
| `E3_artifact_verifiable` | An inspectable artifact binds the action, relevant authority state, timing, and result so a reviewer can validate those bindings without trusting the producer's conclusion. Cryptographic signatures are one route, not a requirement by name. |

Coders MUST assign grades separately to authorization and execution. They MUST
name evidence references and MUST NOT award `E3_artifact_verifiable` merely
because a source uses words such as "verified," "signed," or "audit log."
The verifier, verification method, covered fields, and unresolved gaps belong
in `coding_limitations` or source metadata.

EMILIA MAY produce an artifact evaluated under these rules. So may a database
audit log, signed approval service, workflow engine, insurer, platform, or
independent recorder. No EMILIA identifier, schema, key, service, or verifier is
required. EMILIA-produced evidence has no presumptive grade.

### 6. `execution.status`

| Code | Coding test |
|---|---|
| `proposed_only` | The action was proposed but no execution attempt is evidenced. |
| `blocked` | Execution was attempted but prevented before the side effect occurred. |
| `effected` | The side effect occurred and was not evidenced as reversed at the reporting cutoff. |
| `effect_reversed` | The side effect occurred and was later restored, rolled back, or compensated. This does not imply full remediation or no residual harm. |
| `indeterminate` | Available evidence cannot establish the result. |

Authorization and execution MUST NOT be collapsed. `specific_approval` does not
prove `effected`; `denied` does not prove `blocked`; and `effect_reversed` does
not retroactively authorize the action.

### 7. Minimum validation rules

1. `incident_ref.url` MUST resolve to the named incident when a public registry
   is used.
2. `action_ref` MUST be unique within the incident record.
3. Evidence references MUST resolve to entries in `sources`.
4. A code other than `indeterminate` MUST have a non-empty `basis_summary` and
   at least `E1_party_attested` evidence.
5. `denied`, `revoked`, and `specific_approval` require
   `decision_timing=before_attempt`; otherwise the status MUST be
   `indeterminate` for the pre-attempt snapshot.
6. `outside_scope` MUST identify the evidenced scope boundary and the mismatched
   action property.
7. `authority_absent` MUST cite affirmative evidence of absence, not a search
   that failed to find authority.
8. Coders SHOULD record source access dates and MUST preserve allegations as
   allegations when the underlying incident record does so.

When coders disagree, they SHOULD retain each candidate code and reason in the
working record, then publish `indeterminate` until the conflict is resolved.

### 8. Scope limits

This field group does not:

- assign liability, negligence, fault, culpability, or insurance coverage;
- measure harm likelihood, severity, financial loss, or intent;
- establish that an approver had valid legal or organizational authority;
- verify evidence merely by assigning it a grade;
- prove that an action occurred exactly once or that reversal was complete;
- prescribe a runtime gate, reserve model, access-control system, reporting
  institution, mandatory threshold, or post-reporting response;
- establish AIUC-1 certification, conformance, adoption, endorsement, or a new
  AIUC-1 requirement;
- require EMILIA or any other proprietary implementation; or
- replace AIID, OECD AIM, regulatory reports, or domain-specific incident
  schemas.

The proposal is deliberately narrow: one action, one pre-attempt authorization
state, one separately recorded result, and explicit evidence limits.
