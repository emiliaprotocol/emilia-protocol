# EP Action-Type Profile Registry (land-claim)

*The EMILIA Protocol vertical-profile namespace. Each profile is an action-type family with a
required assurance floor; profiles ride the receipts draft + PIP-012 (envelope/profile registry) and
introduce no new cryptography.*

This document stakes the EP action-type namespace across the verticals where irreversible autonomous
action meets a human-oversight requirement. **Shipped** profiles have a spec + reference; **reserved**
profiles claim the namespace and scope, to be specified as demand lands. Standards strategy: claim
the ground now so the vertical profile is EP's when the regulation arrives, not a competitor's.

## Assurance tiers (floor per action-type)

`software` (valid receipt) < `class_a` (device-bound human signoff) < `quorum` (m-of-n distinct humans).

## Registry

| Action-type family | Vertical | Scope (the irreversible act) | Floor | Status |
|---|---|---|---|---|
| `grid.curtailment` | Energy | Bounded, reversible compute/load curtailment order | class_a (quorum for hard cuts) | **Shipped — PIP-014 / GRACE** |
| `human_oversight.*` | Cross-cutting | In/on-the-loop oversight envelopes (control_mode, scope, window) | class_a | **Shipped — PIP-013** |
| `finance.wire_transfer` · `finance.beneficiary_change` · `finance.trade` | Financial services | Funds movement, payee/bank-detail change, order execution above materiality | class_a → quorum | Reserved |
| `clinical.treatment_order` · `clinical.device_override` · `clinical.trial_mod` | Healthcare | AI-assisted treatment/device action, trial protocol change | class_a | Reserved — see EP-CLINICAL-AUTHORIZATION-PROFILE |
| `gov.benefit_disbursement` · `gov.infrastructure_change` | Government | Benefit pay/deny, infrastructure or records change | class_a → quorum | Reserved |
| `devops.deploy` · `devops.migration` · `devops.secret_rotation` · `devops.permission_grant` | Production change control | Deploy, schema migration, secret rotation, role/permission change | class_a | Reserved (SOC 2 / SOX) |
| `physical.actuation` · `robot.arm_release` · `vehicle.emergency_maneuver` | Robotics / autonomy | Irreversible physical-world actuation; emergency maneuver | class_a (edge-verified) | Reserved — see HUMAN_CONTROL |
| `moderation.content_removal` · `platform.account_suspension` | Content / platform governance | Speech suppression, account action (DSA human-oversight) | class_a | Reserved |
| `defense.engagement_authorization` · `defense.mission_plan` | Defense | Human judgment over force; mission/ROE authorization | quorum | Reserved — DoD 3000.09; civilian-led framing first |
| `infra.safety_override` | Critical infrastructure / nuclear | Safety-system setpoint/override (two-person rule) | quorum | Reserved (long regulatory cycle) |
| `orbital.maneuver` · `maritime.colreg_maneuver` | Space / maritime | Fuel-limited orbital maneuver; COLREGS navigation decision | class_a | Reserved |
| `insurance.claim_payout` · `insurance.denial` | Insurance | Claim pay/deny above threshold | class_a | Reserved |
| `blockchain.high_value_tx` | On-chain | Smart-contract execution above a value threshold | class_a → quorum | Reserved (on-chain verify follow-on) |

## Profile contract (what a profile specifies)

1. The `action_type` string(s) and the `effect_class`.
2. Required fields in the receipt's action object (beyond the EP core).
3. The assurance floor (and when quorum is mandatory).
4. The baseline/method binding, if the vertical references an external accepted methodology
   (e.g. `grid.curtailment` pins the program's curtailment-baseline method hash).
5. Verification predicates beyond the EP core, if any.

## Edge / offline note (a deliberate strength)

Physical-action profiles (`vehicle.*`, `robot.*`, `infra.*`) need sub-second, often air-gapped
verification. EP fits *because* receipts are offline-verifiable: a human pre-authorizes a bounded
on-the-loop envelope (PIP-013), and the edge verifies each act against it in sub-millisecond with no
cloud. Human latency lives at envelope issuance, not per-act — so EP suits latency-critical edge
deployments that cloud-dependent approval systems cannot serve.

*Reserved ≠ built. Reserved profiles claim scope + name; promotion to Shipped requires a spec doc and
a reference vector. New profiles register here first, then (where warranted) as a PIP or I-D.*
