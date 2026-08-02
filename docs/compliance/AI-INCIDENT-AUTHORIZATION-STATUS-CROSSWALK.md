<!-- SPDX-License-Identifier: Apache-2.0 -->

# AI incident authorization-status crosswalk

**Source field group:** `ACTION-AUTHORIZATION-STATUS-v1`

**Review date:** July 31, 2026

**Status:** Proposed interoperability map. It is not an endorsement,
certification, legal opinion, coverage position, or claim that any destination
framework accepts this field group.

## Why this is an extension, not another incident taxonomy

Existing incident frameworks describe what happened, the system and deployment,
the harms and losses, affected entities, suspected causes, and supporting
material. The action-authorization field group adds a narrower forensic view:
what authorization was required for one action, whether authority and action
binding were established, what a named boundary did, what effect followed, and
what evidence supports those statements.

No row below means “equivalent.” It identifies where the added fields could be
carried or referenced without displacing the destination framework's native
semantics.

## Underwriting the Agent Economy blueprint

The blueprint's preliminary shared-database list contains nine field groups.

| Blueprint field | Authorization-status relationship |
| --- | --- |
| Brief summary | A rendering MAY summarize the five independent status axes; the structured record remains authoritative. |
| System type | `action.type` and the boundary role supplement, but do not describe, the model or full system. |
| Deployment | `boundary.id` and `boundary.role` identify the assessed consequence boundary, not the full deployment topology. |
| Harm type | No mapping. Authorization status does not classify harm. |
| Estimated losses | No mapping. The field group does not estimate severity or loss. |
| Entities implicated and impacted | Classifier, boundary, and artifact identifiers can be referenced, but do not determine responsibility or impact. |
| Root causes identified | Invalid, stale, outside-bound, bypassed, or indeterminate values MAY be forensic observations. They are not causal findings by themselves. |
| Forensic data | `evidence.artifacts`, verification state, evidence class, source systems, and limitations are the primary extension point. |
| Metadata | Action reference, action time, evidence time, classification time, classifier, and ruleset digest supplement incident metadata. |

The blueprint says a modular reporting template and matching incident taxonomy
await future work. This proposed field group should be offered as one optional
module, not as the general taxonomy itself.

## OECD common reporting framework

The OECD framework contains 29 criteria across incident metadata, harm details,
AI-system details, and the incident context. The closest extension points are:

| OECD criterion or dimension | Authorization-status relationship |
| --- | --- |
| Criterion 3, relationship of the AI system to the incident | The field group records action and boundary facts; it does not decide direct cause, contributing factor, failure to act, misuse, or human error. |
| Criterion 7, supporting material | Artifact digests and verification states can index supporting material without embedding confidential evidence. |
| Criteria 8–9, system/product and organizations | Action and boundary identifiers can be linked to the native system and organization records. |
| Criteria 10–12, severity, harm type, and harm quantification | No mapping. Those remain OECD-native fields. |

The OECD framework is a reporting benchmark. This field group does not make an
incident report complete and does not determine whether an event is an AI
incident.

## AI Incident Database

The AI Incident Database supports multiple contributed taxonomies rather than
one canonical interpretation. The field group could be proposed as an
additional classification with these boundaries:

- CSET's high-level action/function and assurance-related fields provide system
  context; they do not establish per-action authorization status.
- GMF separates known from potential technical failure causes and grounds labels
  in snippets and discussion. Authorization status should preserve the same
  distinction through `indeterminate`, artifact verification states, and
  limitations rather than translating conjecture into `valid`, `invalid`, or
  `bypassed`.
- AIID incident and report identifiers should remain native identifiers. An
  authorization-status record may reference them but must not replace them.

Any submission to AIID remains subject to its maintainers' quality, completeness,
and governance requirements.

## EU AI Act Article 73

Article 73 requires providers of high-risk AI systems to report serious
incidents, investigate them, perform a risk assessment, and take corrective
action within the applicable legal process and deadlines.

Authorization-status records MAY support an investigation by preserving action,
boundary, evidence, and timing facts. They do not:

- establish that an event is a “serious incident”;
- establish a causal relationship or reasonable likelihood of one;
- start, stop, or satisfy a reporting deadline;
- replace the Commission's reporting template; or
- demonstrate legal compliance.

The Commission has sought alignment between its reporting work and the OECD AI
Incidents Monitor and common reporting framework. That makes a narrow crosswalk
preferable to an incompatible replacement format.

## Zhu's agentic-AI insurance model

Zhu defines `h_i(u)` as a human-approval indicator for an action and `beta_i` as
an aggregate operational-authority variable. `ACTION-AUTHORIZATION-STATUS-v1`
does not replace or validate that model.

The record can supply more granular observations about one action:

- whether authorization was exact, bounded, standing, absent, or unknown;
- whether authority was valid, invalid, revoked, stale, or indeterminate;
- whether evidence matched the action;
- whether a named boundary admitted, refused, or was bypassed; and
- whether the effect executed, failed, remained indeterminate, or is unknown.

An actuary MAY derive model inputs from a governed population of these records,
but the derivation, weighting, predictive validity, and pricing use remain the
actuary's responsibility. Evidence classes are ordinal labels, not numeric risk
weights.

## Claim boundary

This crosswalk does not claim novelty over incident reporting, human-approval
indicators, operational-authority ratios, or insurance telemetry. It does not
claim adoption by the blueprint authors, OECD, AIID, the European Commission,
AIUC, ACORD, LMA, NIST, any carrier, or any reinsurer.

The proposed contribution is narrower: a closed and testable way to preserve
action-level authorization facts and their evidence limitations across systems
that otherwise use different incident and claims formats.
