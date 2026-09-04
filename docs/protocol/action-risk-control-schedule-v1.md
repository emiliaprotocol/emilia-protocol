# Action Risk Control Schedule v1

`EP-ACTION-RISK-CONTROL-SCHEDULE-v1` is a signed list of technical conditions for one action class at one provider boundary. It lets a relying party, risk reviewer, or other authorized evaluator ask a narrow question: did this deployment present the exact control configuration and a current qualification observation required by this schedule?

The answer is one of `ELIGIBLE`, `NOT_ELIGIBLE`, or `INDETERMINATE`. Only `ELIGIBLE` means the scheduled technical requirements were observed. It is still not permission to execute.

## Claim boundary

The schedule is not an insurance policy, binder, endorsement, coverage certificate, premium decision, legal opinion, or allocation of liability. It does not authorize an action, prove that a provider effect happened, establish complete mediation, or make the facts in referenced evidence true. A carrier, broker, customer, or other relying party remains responsible for its own policy, underwriting, authorization, and claims decisions.

Every evaluation result carries:

```json
{
  "authorizes_action": false,
  "establishes_policy": false,
  "establishes_coverage": false,
  "sets_premium": false,
  "allocates_liability": false,
  "proves_provider_effect": false
}
```

The fixed claim-boundary value is:

```text
technical_control_requirements_only_not_policy_coverage_premium_liability_action_authorization_or_effect_proof
```

## What the schedule binds

The closed JSON object binds all of the following under one hybrid signature:

- schedule, issuer, relying-party, and tenant identities;
- issuance, activation, and expiry instants;
- action class plus the exact CAID profile identifier and digest;
- provider, account, environment, and adapter digest;
- qualification requirements, status authority, status key, minimum sequence, and maximum observation age;
- exact AEB, AEC, and local-policy digests;
- complete-mediation surface-inventory and refusal-probe evidence digests;
- loss-allocation program digest;
- Open Exposure Ledger program and digest, currency, per-action ceiling, aggregate ceiling, reconciler, and reconciliation deadline;
- required Outcome Binding source roles and classes, quorum, observation windows, and control-domain independence;
- fixed handling for indeterminate and divergent outcomes; and
- exactly two schedule-level trust pins: the schedule issuer and qualification-status authority.

The two trust-pin references inside the schedule are signed configuration
references. They are not trust roots. A reference's `key_digest` is the
canonical SHA-256 digest of `{issuer_id, key_id, public_key, pq_public_key}`.
Verification keys arrive separately from the caller through
`trusted_schedule_keys` and `trusted_status_keys`, and the evaluator checks
those two external pins against the signed reference digests. A self-presented
key never becomes trusted because the artifact mentions it.

Native-component keys and provider-observer keys are deliberately not listed
as v1 schedule trust references. The relying party supplies them to its native
adapters and provider-outcome verifier. Those verifiers remain trust inputs and
must enforce their own key, artifact, subject, state, freshness, and continuity
rules. A future version needs a typed role/source-to-key mapping before it can
claim schedule-to-native pin agreement; decorative key digests are not enough.

## Hybrid proof

The schedule uses the shared `EP-RISK-HYBRID-v2` proof with both `Ed25519` and `ML-DSA-65` required under `hybrid_all`. The registered algorithm set is committed inside the signed bytes. The proof must contain exactly two signature entries in registered order, and each entry's `key_id` must equal both `proof.key_id` and `issuer.key_id`. Removing either signature or key identifier, changing an identifier, narrowing the set, changing a field, or substituting either externally pinned key makes verification fail.

The ML-DSA-65 implementation is the repository's pure-JavaScript FIPS 204 implementation. It is not a FIPS-validated cryptographic module, and this profile makes no certification claim.

## Evaluation inputs

`evaluateActionRiskControlSchedule(schedule, options)` requires:

1. the expected schedule, issuer, relying-party, and tenant identifiers;
2. externally provisioned schedule and qualification-status trust roots;
3. a closed `observed_controls` object matching every scheduled technical binding; and
4. a current `EP-ACTION-RISK-QUALIFICATION-STATUS-v1` artifact from the scheduled status authority; and
5. the relying party's durable last-seen qualification-status head.

`observed_controls` is a caller assertion. The evaluator matches it byte for
byte to the signed schedule, but it does not prove that the referenced control
digests describe what is actually deployed. The separately trusted
qualification process, native verifiers, and operational evidence must
establish that fact.

The qualification status binds the schedule digest, tenant, qualification-requirements digest, monotonic sequence, observation time, evidence digest, and one of the same three outcomes. It is independently hybrid-signed. It is also evidence only and never authorizes an action.

The last-seen head is a closed relying-party input binding the schedule identifier and digest, tenant, status authority and key, greatest verified sequence, corresponding signed-status digest, and local recording time. A presented status below that sequence is a rollback and returns `NOT_ELIGIBLE`. A different status at the same sequence is an equivocation and also returns `NOT_ELIGIBLE`. A higher valid sequence can advance the head. If no head is available, the result is `INDETERMINATE`, never `ELIGIBLE`.

The evaluator does not make the caller's head durable. The relying party must keep and monotonically update it in rollback-resistant storage. Supplying an old or fabricated head defeats the caller-side continuity assumption and remains outside this artifact's claim.

## Result semantics

| Outcome | Meaning | Execution consequence |
| --- | --- | --- |
| `ELIGIBLE` | Both hybrid proofs verify under external pins, all exact bindings match, the schedule is active, the qualification status is current relative to the relying party's last-seen head, and that status is `ELIGIBLE`. | Persist any higher verified head, then continue to the separate local authorization and provider-entry checks. |
| `NOT_ELIGIBLE` | A signature, pin, schema, identity, validity, or exact control binding is wrong, or the status authority reports `NOT_ELIGIBLE`. | Fail closed. Do not treat the schedule as permission. |
| `INDETERMINATE` | Current qualification cannot be established, including a missing, old, or stale status or an unavailable ML-DSA verifier. | Refuse retry, preserve open exposure, and require reconciliation. |

The required indeterminate handling is:

```text
REFUSE_RETRY_PRESERVE_OPEN_EXPOSURE_REQUIRE_RECONCILIATION
```

The required divergent handling is:

```text
REFUSE_CLOSEOUT_PRESERVE_OPEN_EXPOSURE_ESCALATE
```

## Canonical ordering

`outcome_binding.required_sources` is sorted by `role`, then `source_class`,
using ASCII order. `trust_pin_references` contains exactly
`QUALIFICATION_STATUS` followed by `SCHEDULE_ISSUER`, in canonical ASCII order.
Duplicates, extra purposes, sparse arrays, accessors, unknown object members,
non-canonical monetary strings, a per-action ceiling above the aggregate
ceiling, and a quorum larger than the source set are refused.

## API

```ts
import {
  actionRiskControlScheduleDigest,
  actionRiskQualificationStatusDigest,
  evaluateActionRiskControlSchedule,
  signActionRiskControlSchedule,
  signActionRiskQualificationStatus,
} from './src/action-risk-control-schedule.js';
```

- `signActionRiskControlSchedule(input, signer)` validates the closed source object and signs it with both required algorithms.
- `actionRiskControlScheduleDigest(artifact)` returns the canonical SHA-256 digest of the complete signed artifact.
- `actionRiskQualificationStatusDigest(artifact)` returns the canonical SHA-256 digest stored with the relying party's last-seen status head.
- `signActionRiskQualificationStatus(input, signer)` creates the independently signed current-status artifact.
- `evaluateActionRiskControlSchedule(artifact, options)` verifies both artifacts, applies exact caller context, checks time and sequence, compares every observed control, and returns only the three-result vocabulary.

The schedule JSON Schema is published at
`public/schemas/ep-action-risk-control-schedule.schema.json`. The separately
signed qualification-status schema is published at
`public/schemas/ep-action-risk-qualification-status.schema.json`.

The local `qualification_status_head` is not a signed protocol artifact. It is
caller-owned continuity state, supplied to the evaluator and kept in the
relying party's rollback-resistant storage. Its closed fields are
`schedule_id`, `schedule_digest`, `tenant_id`, `status_authority_id`,
`status_key_id`, `sequence`, `status_digest`, and `recorded_at`.

## Deliberate non-claims

This v1 does not establish:

- that a policy exists or responds to a loss;
- that any insurer, broker, regulator, auditor, or customer has accepted the schedule;
- premium credit or pricing effect;
- legal causation, liability, enforceability, solvency, or claims payment;
- truth or completeness of a surface inventory, refusal probe, status observation, provider record, or outcome source;
- schedule-to-native or schedule-to-provider key agreement; those keys remain relying-party adapter inputs in v1;
- rollback resistance when the relying party does not durably preserve and advance its last-seen qualification-status head;
- complete mediation on a path that bypasses the configured enforcement point; or
- independent implementation or production deployment.

The artifact makes technical requirements portable and tamper-evident. It leaves commercial and legal decisions with the parties that own them.
