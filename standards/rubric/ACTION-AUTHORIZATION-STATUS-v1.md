<!-- SPDX-License-Identifier: Apache-2.0 -->

# Action Authorization Status and Evidence Field Group v1

**Identifier:** `ACTION-AUTHORIZATION-STATUS-v1`

**Status:** Proposed implementation-neutral field group. This is not an IETF
Internet-Draft, insurance standard, rating rule, coverage determination, or
claim of adoption.

## 1. Purpose

AI incident and claims records commonly describe the system, deployment, harm,
loss, entities, suspected causes, forensic material, and incident metadata.
Those fields do not answer a narrower question:

> For this action, at this named consequence boundary, what authorization was
> required, what authority and action binding existed, what did the boundary
> do, what effect followed, and what evidence supports the classification?

This field group answers that question without replacing a broader incident or
loss taxonomy. It is designed to be embedded in, or cross-referenced by,
existing reporting formats.

The unit is one action at one named boundary. A system-wide label such as
“human supervised” is not a substitute.

## 2. Claims this field group does not make

A conforming record does not establish:

- that an AI system caused a loss;
- that a person or organization is at fault;
- that an action or loss is covered under an insurance contract;
- that every consequential action entered the reported boundary;
- that the named source systems constitute the complete population; or
- that a verified artifact was adequate under a relying party's policy.

The record classifies available evidence. It does not turn that evidence into
authorization, liability, or coverage.

## 3. Five independent status axes

The axes MUST remain separate. A producer MUST NOT infer one from another.

### 3.1 Authorization requirement

| Code | Meaning |
| --- | --- |
| `exact_action` | The policy required authorization bound to this exact material action. |
| `bounded_program` | The policy allowed an action reachable within a bounded, authorized program. |
| `standing_scope` | The policy relied on a standing scope or role rather than action-specific approval. |
| `none` | The established policy imposed no authorization requirement for the action. |
| `unknown` | The applicable requirement could not be established. |

### 3.2 Authority state

| Code | Meaning |
| --- | --- |
| `valid` | The presented authority was current and valid under the evaluated rules. |
| `invalid` | The presented authority failed those rules. |
| `revoked` | The authority was revoked at the relevant evaluation time. |
| `stale` | Freshness requirements were not met. |
| `indeterminate` | Available evidence could not establish the state. |
| `not_evaluated` | No authority evaluation applied or occurred. |

### 3.3 Action binding

| Code | Meaning |
| --- | --- |
| `exact_action` | Evidence bound the exact material action. |
| `within_bound` | The action was within a stated program or standing bound. |
| `outside_bound` | The action fell outside the evidence's bound. |
| `none` | The evidence contained no action binding. |
| `indeterminate` | The binding relation could not be established. |
| `not_evaluated` | No binding evaluation applied or occurred. |

### 3.4 Admission state at the named boundary

| Code | Meaning |
| --- | --- |
| `admitted` | The boundary admitted the action. |
| `refused` | The boundary refused the action. |
| `bypassed` | The action reached an effect path without traversing the named required boundary. |
| `indeterminate` | Available evidence cannot establish the boundary decision. |
| `not_observed` | No boundary observation is available. |

### 3.5 Observed effect

| Code | Meaning |
| --- | --- |
| `executed` | The material effect was observed as executed. |
| `failed` | An attempted effect failed. |
| `not_executed` | Evidence establishes that the effect did not execute. |
| `indeterminate` | Entry occurred or may have occurred, but the outcome is unresolved. |
| `unknown` | No reliable effect determination is available. |

Combinations that look contradictory are often the incident. A record MAY say
`refused` and `executed` when one boundary refused but the effect was observed
through another or unmediated path. It MAY say `admitted` with `invalid`
authority when a boundary made an erroneous decision. Consumers MUST preserve
those combinations rather than “correcting” them.

## 4. Evidence classes

The evidence class describes support for the classification, not the quality of
the underlying authorization policy.

| Class | Meaning |
| --- | --- |
| `E0_NONE` | No supporting artifact is available. |
| `E1_SELF_ASSERTED` | A party states the classification without an operator record sufficient to recheck it. |
| `E2_OPERATOR_RECORDED` | An operator-controlled record supports the classification. |
| `E3_ACTION_BOUND_SIGNED` | At least one successfully verified signed artifact binds one or more classification claims to the action. |
| `E4_OFFLINE_PINNED_VERIFIABLE` | A verifier can recheck at least one verified artifact offline using the explicitly identified and digest-pinned verification profile. This does not imply an independently operated issuer. |
| `E5_RECONCILED_NAMED_POPULATION` | Action records were reconciled against explicitly named systems for a stated population. This does not prove that unnamed or bypass paths did not exist. |

Most historical incidents will begin at `E0`, `E1`, or `E2`. A deployment MUST
NOT be assigned `E3` merely because an unchecked signature exists, MUST NOT be
assigned `E4` without binding the verification profile used, and MUST NOT be
assigned `E5` without naming the reconciled systems.

Every record MUST include a non-empty `limitations` array. An evidence class is
not a universal confidence score and MUST NOT be averaged as if the distance
between adjacent classes were numeric.

## 5. Record shape

The normative machine-readable shape is defined by:

- [`public/schemas/action-authorization-status.v1.schema.json`](../../public/schemas/action-authorization-status.v1.schema.json)
- [`standards/staged/action-authorization-status.v1.vectors.json`](../staged/action-authorization-status.v1.vectors.json)
- [`standards/staged/action-authorization-status.reference.ts`](../staged/action-authorization-status.reference.ts)
- [`standards/staged/action-authorization-status.selftest.ts`](../staged/action-authorization-status.selftest.ts)

The vectors are staged outside the governed live conformance manifest until an
external implementation runs them and the clean-room bundle is re-frozen. A
same-team implementation is not counted as independent interoperability.

The top-level members are closed:

```json
{
  "@version": "ACTION-AUTHORIZATION-STATUS-v1",
  "action": {
    "reference": { "scheme": "caid", "value": "caid:1:example:release-payment" },
    "type": "payment.release",
    "occurred_at": "2026-07-30T18:00:00Z"
  },
  "boundary": { "id": "gate:production", "role": "provider_gateway" },
  "classification": {
    "requirement": "exact_action",
    "authority": "valid",
    "binding": "exact_action",
    "admission": "admitted",
    "effect": "executed"
  },
  "evidence": {
    "class": "E4_OFFLINE_PINNED_VERIFIABLE",
    "as_of": "2026-07-30T18:05:00Z",
    "population_basis": "single_action",
    "source_systems": ["gate:production"],
    "verification_profile": {
      "id": "ep-verify:3.14.0",
      "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "artifacts": [{
      "type": "authorization-receipt",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "verification": "verified"
    }],
    "limitations": [
      "This classification does not establish causation, legal liability, coverage, or population completeness."
    ]
  },
  "classified_at": "2026-07-30T18:06:00Z",
  "classifier": {
    "id": "adjuster:example",
    "method": "mixed",
    "ruleset_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

The action reference is scheme-neutral. CAID is one available scheme; use of
this field group does not require adoption of CAID or any EMILIA receipt.

## 6. Population and ratio discipline

This field group can support period summaries only after the denominator is
defined. A summary MUST state:

1. the period;
2. the action classes in scope;
3. every named source system used to construct the population;
4. unknown, unclassified, and unmatched records;
5. the population basis and evidence class; and
6. known routes that could bypass collection.

A ratio such as “fraction of consequential actions admitted with exact-action
authorization” MUST NOT be called a coverage rate unless the numerator and
denominator share the same named population and unknowns remain visible.
Reconciliation against named systems is not proof that no unnamed system or
credential path existed.

## 7. Prior art and contribution boundary

The idea that human approval and operational authority affect agent risk is not
new. Quanyan Zhu's July 2026 paper defines a per-action human-approval indicator
and an aggregate operational-authority variable for agentic-AI insurance.

This field group's narrower contribution is engineering semantics for an
incident or claims record: five non-collapsing action-level axes, a named
admission boundary, evidence classes, closed validation, explicit unknowns, and
population limitations. It does not claim a new actuarial model.

The July 2026 *Underwriting the Agent Economy* blueprint proposes a shared AI
incident database with nine preliminary field groups and says a modular
reporting template and matching taxonomy await future work. This document is a
proposed authorization-status extension, not a competing general taxonomy.

## 8. Versioning and governance

Version 1 is closed. Unknown members are invalid rather than silently ignored.
New codes require a version change, definitions, at least one positive vector,
at least one confusion or laundering vector, and a published explanation of
the evidence and population consequences.

Suggested corrections and external mappings should be proposed against the
rubric and vectors, not against a vendor implementation.

## 9. References

- *Underwriting the Agent Economy: The Blueprint for an AI Insurance Stack*, July 2026: <https://arxiv.org/abs/2607.11999>
- Quanyan Zhu, *AI-Native Insurance for Agentic AI: Pricing, Underwriting, and End-to-End Automation*, July 2026: <https://arxiv.org/abs/2607.13230>
- OECD, *Towards a Common Reporting Framework for AI Incidents*, February 2025: <https://doi.org/10.1787/f326d4ac-en>
- AI Incident Database taxonomies: <https://incidentdatabase.ai/taxonomies/>
- EU AI Act, Article 73: <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-73>
