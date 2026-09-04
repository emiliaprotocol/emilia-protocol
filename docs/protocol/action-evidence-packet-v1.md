# Action Evidence Packet v1

`EP-ACTION-EVIDENCE-PACKET-v1` joins the technical records for one exact Gate action. It gives a relying party one content-addressed container to inspect, while leaving each native artifact under its own verifier and trust policy.

The packet is an orchestration format. It does not turn a callback result into proof, certify the callback, or replace native signature verification. It also does not decide insurance coverage, causation, liability, a claim, or payment.

The fixed claim boundary is:

```text
technical_evidence_join_for_one_exact_action_not_insurance_coverage_not_claim_adjudication_not_causation_not_liability_not_payment
```

## What is bound

The manifest binds one closed provider context:

- tenant, admission, and operation identifiers;
- admission-snapshot, action, and effect-request digests;
- CAID;
- provider, account, environment, and adapter;
- idempotency key;
- provider outcome; and
- the shared provider-event time, `observed_at`.

It also binds the evaluated Action Risk Control Schedule, every component reference and expected native state, and a bounded set of provider-outcome proofs. The manifest and every attachment are addressed with canonical SHA-256 digests. An attachment key must equal the digest recomputed from its value. Missing attachments, unreferenced attachments, duplicate content used in two roles, and unknown fields fail closed.

The packet accepts at most 64 attachments and 16 MiB of canonical JSON. The 64-entry bound leaves room for 16 outcome sources, each with a binding and an observation, plus the schedule and all 15 component roles.

## Provider outcome bridge

Each `EP-PROVIDER-OUTCOME-BINDING-v1` carries the exact provider context, its digest, and the digest of a complete `EP-OUTCOME-OBSERVATION-v2`. A digest by itself is never evidence.

The bridge verifier checks the full Outcome Observation v2 under source keys supplied out of band by the relying party. It then checks the exact source identity, action digest, CAID, operation, and the signed observed-effect commitment to the provider-context digest. The provider context includes `tenant_id`, `admission_id`, `operation_id`, `snapshot_digest`, `caid`, `action_digest`, `effect_request_digest`, `provider`, `account`, `environment`, `adapter_id`, `idempotency_key`, `outcome`, and `observed_at`. A substitution in any field changes the digest and is refused.

`observed_at` is the shared provider-event time. It is not forced to equal every source's `observed_until`. Each independent source keeps its own signed `observed_from`, `observed_until`, and `attested_at` interval.

Presenter-supplied keys are not accepted. A source with a missing, stale, retired outside the relevant time, or compromised pin cannot satisfy the bridge.

## Schedule-controlled source quorum

The packet does not invent its own source policy. A trusted schedule adapter must return the source roles and classes, quorum, observation window, and control-domain rule read from the verified `EP-ACTION-RISK-CONTROL-SCHEDULE-v1` artifact. The normalized result is closed and bound back to the recomputed schedule digest, exact subject, and manifest evaluation.

The schedule requires at least two source classes and a quorum of at least two. A provider proof counts only when:

- its role and source class match a distinct required schedule slot;
- the complete hybrid-signed Outcome Observation v2 verifies;
- its source ID is unique in the packet; and
- its external source pin has a `control_domain_id` distinct from the other sources counted toward the quorum.

`TECHNICALLY_COMPLETE` is impossible when the verified schedule result omits the source set, quorum, observation window, or independence rule. It is also impossible when the verified proofs do not meet both the source quorum and the control-domain quorum.

## Observation window

The relying party supplies an externally verified provider-entry time. The verified schedule supplies:

```json
{
  "opens_before_provider_entry_sec": 0,
  "closes_after_provider_entry_sec": 180,
  "max_observation_age_sec": 180
}
```

The packet verifier derives the allowed interval from those values. Every counted source interval must start no earlier than the scheduled opening, contain the shared provider event, and end no later than the scheduled close. The shared event must occur at or after provider entry. The signed source attestation must predate packet assembly, and assembly must predate the verification time.

Freshness is measured from each source's signed `observed_until`. The schedule's `max_observation_age_sec` is the ceiling. A caller may supply a lower maximum age, but a larger value cannot widen the signed schedule.

`assembled_at` is not a security clock. The manifest is content-addressed, not signed by the assembler, so that field provides internal chronology only. Schedule currentness, source currentness, and native-artifact currentness come from their verified artifacts and external trust inputs. A deployment that needs assembler identity or packet-level non-repudiation should place the complete packet digest in a separately signed envelope.

## Native component adapters

The required component roles are:

| Role | Required normalized state |
| --- | --- |
| `aeb` | `SATISFIED` |
| `admission_snapshot` | `IMMUTABLE` |
| `admission_decision` | `ALLOW` |
| `qualification_statement` | `QUALIFIED` |
| `qualification_status_head` | `CURRENT` |
| `open_exposure_ceiling` | `ACTIVE` |
| `open_exposure_record` | terminal OEL state |
| `open_exposure_history` | matching terminal OEL state |
| `observed_effect_relation` | observed, divergent, or indeterminate |
| `coverage_surface` | technical mediation state |
| `refusal_probe` | refusal-probe result |
| `supplied_population_report` | `VERIFIED_SUPPLIED_POPULATION` |

`loss_report`, `recourse`, and `loss_allocation` are optional. When present, they must be verified like every required component.

For each role, the relying party supplies a native adapter. The adapter must return its own recomputed artifact digest, exact subject digest, normalized state, verification result, and currentness result. The orchestrator compares those values with the manifest. It does not inspect a generic object and assume that the expected state is true.

Production adapters must call the native artifact verifier with externally provisioned trust roots and currentness inputs. A callback that merely echoes the request can only manufacture an application assertion; this module does not make that assertion trustworthy.

## Cross-record consistency

The verifier also checks the joined records against each other:

- the OEL record and history must have the same terminal state;
- that terminal state must agree with `COMMITTED`, `PROVEN_NOT_COMMITTED`, or `INDETERMINATE` from the provider context;
- a divergent observed-effect relation is a conflict;
- an indeterminate outcome or relation stays indeterminate;
- an executed-without-receipt probe is a conflict;
- `coverage_surface: ungated` is a conflict;
- `coverage_surface: witness_only` is incomplete; and
- only `coverage_surface: gated` with a successful refusal probe can reach `TECHNICALLY_COMPLETE`.

Here, `coverage_surface` means technical enforcement-path coverage. It is not insurance coverage.

## Results

The verifier returns only four results:

| Result | Meaning |
| --- | --- |
| `TECHNICALLY_COMPLETE` | Every referenced artifact is present, every supplied trusted adapter reports an exact current binding, the signed schedule is eligible, the provider source and control-domain quorums are met, the observation window is satisfied, the surface is gated, and the joined states agree. |
| `INCOMPLETE` | Required evidence, a verifier, a current result, a source, a control domain, or a quorum is missing. |
| `CONFLICTED` | Content addressing, an exact binding, a signed schedule rule, chronology, source policy, gating state, refusal probe, or terminal state conflicts with the packet. |
| `INDETERMINATE` | A native adapter, schedule, provider outcome, observed-effect relation, or technical surface cannot currently be resolved. |

Conflict takes precedence over indeterminate, which takes precedence over incomplete. `TECHNICALLY_COMPLETE` means only that this technical evidence join passed the configured verification boundary. It is never a coverage determination or claims decision.

## API

```ts
import {
  actionEvidenceArtifactDigest,
  actionEvidenceManifestDigest,
  buildActionEvidencePacket,
  verifyActionEvidencePacket,
} from './src/action-evidence-packet.js';
import {
  buildProviderOutcomeBinding,
  providerOutcomeContextDigest,
  providerOutcomeObservationEffects,
  verifyProviderOutcomeBinding,
} from './src/provider-outcome-binding.js';
```

`buildActionEvidencePacket` validates the closed manifest and content-addressed attachment set. `verifyActionEvidencePacket` orchestrates the schedule adapter, native component adapters, and provider bridge under caller-supplied trust and currentness inputs.

The public JSON Schema is `public/schemas/ep-action-evidence-packet.schema.json`. Schema validity checks structure only. It cannot verify a signature, trust a key, establish currentness, satisfy a quorum, prove complete mediation, or establish that a provider effect happened.

## Deliberate limits

This v1 does not prove that a source told the truth, that a supplied population
is complete, that an inventory found every bypass, or that the provider
performed the physical or legal effect described by its records. It does not
establish schedule-to-native or schedule-to-provider key agreement; the
relying party supplies those adapter trust inputs separately. It does not
establish that a carrier, broker, customer, auditor, or regulator has accepted
the packet. It does not create a policy, set a premium, determine coverage,
allocate liability, adjudicate a claim, or promise payment.
