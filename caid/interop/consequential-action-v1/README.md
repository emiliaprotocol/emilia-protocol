# Consequential Action Interoperability Project

This directory contains 25 **candidate**, version-pinned mappings between
consequential-action mechanisms and one local CAID action definition.

The project asks a deliberately narrow question:

> After an artifact verifies under its own specification, can its material
> action be projected without loss into the same typed action that another
> mechanism describes?

The answer is not forced to be yes. The source-audited review produces:

- 2 `COMPLETE` CAID-field extractions, of which one is lossless and one
  deliberately returns `INDETERMINATE` because the source action identity
  commits additional semantics;
- 8 `PARTIAL` bindings that return `INDETERMINATE`;
- 15 `ABSENT` bindings that return `INDETERMINATE`; and
- an explicitly non-normative, optional carry profile for every target.

No author validation or endorsement is claimed. The intended next step is
author review: “Here is our pinned reading of your action model. What did we
get wrong?”

The ORPRG revision -00 entry records narrow author feedback received on
2026-07-28. It removes the earlier `/effect_request/*` candidate paths: those
are not native JSON members defined by the draft. ORPRG binds the complete
canonical external-effect request under an identified profile, but a CAID
projection into `operation`, `target_ref`, and `parameters_digest` requires
that effect-specific profile and the verified canonical request. The entry
therefore remains `PARTIAL` to `INDETERMINATE`. Policy epoch and authorization
audience remain verifier context. This feedback is not validation of the CAID
harness or broader pack, nor implementation, adoption, or endorsement.

## Why the local action type is not in the public registry

`consequence.invoke.1` is local to this project. It commits to:

- operation;
- target;
- complete material parameters.

Authorization audience and trust configuration stay outside the action
identifier. The action target identifies where the material operation occurs.

The project does not add 25 speculative types to CAID's public registry.
CAID explicitly permits local definition files in the same schema. A public
type should be proposed only after domain practitioners validate its material
fields.

## What “native” means here

The native side of each vector is a **human-reviewed extraction fixture** from
the pinned draft revision. It is not a production parser and it does not test a
draft's native signature, trust roots, or authorization semantics. Fixture-time
native verification is a precondition.

Each manifest entry now classifies every material field separately. A mapped
field records its source path, transform, and whether that path is a native
wire field, an abstract-model field, or deterministic adapter output. An
unavailable field has a null source path and an explanation. Candidate native
paths are never published for fields marked unavailable.

Completeness of the three local CAID fields is not sufficient for equivalence.
If the source protocol makes additional fields material to its own action
identity, the manifest records them under `projection_loss`, the mapping
profile declares `declared-source-semantic-loss`, and every implementation
returns `INDETERMINATE`. The profile never silently erases source semantics.

For transport formats such as HTTP Message Signatures, an extraction may be
deterministic adapter output after native verification. For architecture and
gap-analysis drafts that define no wire object, all material source paths are
null and the result is `INDETERMINATE`.

The executable native refusal probe still needs a syntactically complete CAID
mapping profile. It uses reserved `/__caid_unavailable__/*` sentinel paths for
unavailable fields. Those sentinels are deliberately absent from the fixture,
are not source-draft fields, and must produce `INDETERMINATE`.

## What the optional carry profile means

The carry profile shows one non-breaking composition path:

```json
{
  "caid_action": {
    "operation": "medical.coverage.determine",
    "target": "urn:claim:example:2026:00042",
    "parameters": {
      "requested_service": "J3490",
      "amount": "1280.00",
      "currency": "USD"
    }
  }
}
```

This is not a claim that any source draft defines, accepts, or should adopt that
member. A mechanism can instead carry an equivalent native field, digest, or
external reference under a profile its authors prefer.

## Executable evidence

Every target has four vectors:

1. its candidate native result (`EQUIVALENT_UNDER_PROFILE` or
   `INDETERMINATE`);
2. an optional-carry equivalence result;
3. a material parameter mutation returning `NOT_EQUIVALENT`; and
4. missing material parameters returning `INDETERMINATE`.

All 100 vectors run in dependency-free JavaScript, Python, and Go and must
produce identical verdicts and refusal reasons:

```sh
npm run caid:conformance
npx vitest run caid/interop/consequential-action-v1/*.test.mjs
```

The generator is governed:

```sh
node caid/interop/consequential-action-v1/generate.mjs --check
```

## Target set

| Native result | Mechanism |
| --- | --- |
| ABSENT | `draft-klrc-aiagent-auth-03` |
| ABSENT | `draft-mcguinness-oauth-ai-agent-instance-00` |
| PARTIAL | `draft-noa-scitt-ai-agent-receipt-00` |
| ABSENT | `draft-ietf-wimse-arch-08` |
| PARTIAL | `draft-ietf-wimse-http-signature-05` |
| ABSENT | `draft-ietf-wimse-workload-creds-02` |
| ABSENT | `draft-ietf-wimse-wpt-01` |
| ABSENT | `draft-bu-agentproto-security-principal-binding-03` |
| ABSENT | `draft-rosomakho-oauth-txn-challenge-00` |
| PARTIAL | `draft-nelson-agent-delegation-receipts-10` |
| PARTIAL | `draft-jiang-oauth-intent-admission-00` |
| ABSENT | `draft-araut-oauth-transaction-tokens-for-agents-02` |
| COMPLETE | `draft-coetzee-oauth-spt-txn-tokens-03` |
| ABSENT | `draft-mcguinness-oauth-actor-profile-00` |
| ABSENT | `draft-rampalli-cross-org-delegation-mapping-05` |
| PARTIAL | `draft-mih-scitt-agent-action-capsule-sel-disc-00` |
| PARTIAL | `draft-emirdag-scitt-ai-agent-execution-00` |
| ABSENT | `draft-lee-orprg-permit-receipts-00` |
| PARTIAL | `draft-baur-pap-02` |
| COMPLETE fields / declared loss / INDETERMINATE | `draft-pidlisnyi-aps-03` |
| ABSENT | `draft-howe-vcon-agent-session-00` |
| PARTIAL | `draft-pei-opsawg-agentops-observability-00` |
| ABSENT | `draft-dunbar-dmsc-gw-scenarios-gap-analysis-02` |
| ABSENT | `draft-soden-wellknown-mcp-commerce-00` |
| ABSENT | `draft-hopley-x402-compliance-receipt-02` |

The exact source revision, official archive URL, SHA-256, evidence locator,
candidate profiles, missing material fields, and author-review question for
each mechanism are in `manifest.json`.

## Claim boundary

Mapping is content correlation, not authorization. It does not establish
identity, authority, consent, safety, policy acceptance, execution, or outcome.
It never converts an `INDETERMINATE` result into equivalence. Each source
artifact must first verify under its own specification and relying-party trust
configuration.
