# EP Action Control Manifest

Status: experimental, additive profile.  
Current artifact: `EP-ACTION-CONTROL-MANIFEST-v0.2` at `/.well-known/agent-action-control.json`.

## The Missing Waist

The adjacent standards work is converging on evidence objects:

| Lane | What it covers | What it leaves to deployments |
| --- | --- | --- |
| [SCITT / RFC 9943](https://datatracker.ietf.org/doc/rfc9943/) | Signed-statement transparency and third-party verifiability | Which AI actions require which authorization evidence |
| [SCRAPI](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/) | REST API for registering statements in a transparency service | The semantic control policy for each action |
| [Pre-Execution AI Action Authorization Records](https://datatracker.ietf.org/doc/draft-munoz-scitt-permit-profile/) | A SCITT Permit proving a request was authorized before dispatch | Which action families require a permit and which fields must bind |
| [AI-Agent Action Receipts](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/) | Tamper-evident record of action, principal, policy identity, and verdict | Whether the action needed human approval or system-of-record binding |
| [Agent Action Capsules](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/) | Post-verdict capsule for executed, blocked, denied, or errored actions | Which evidence profile is required before/after the effect boundary |
| [WIMSE Authorization Evidence](https://datatracker.ietf.org/doc/draft-munoz-wimse-authorization-evidence/) | Signed evidence for WIMSE-authorized agent actions | The action-risk declaration and human-assurance requirement |
| [OAuth Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | Propagates identity and authorization context through a trusted call chain | Consequence classification and offline reliance evidence |
| [XAIP Receipts](https://datatracker.ietf.org/doc/draft-xkumakichi-xaip-receipts/) | Signed execution receipts for tool calls | Scoring policy, aggregation, and reactive behavior |
| [Signed Decision Receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) | Portable signed access-control decisions | The manifest that says which irreversible actions require them |
| [Delegation Receipt Protocol](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/) | User-signed delegation object before runtime control | Per-action system-of-record execution binding and evidence output |
| [Attested Inference Receipt](https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/) | TEE-linked evidence for confidential inference | Human authorization and irreversible-effect policy |

The gap is not another receipt format. The gap is the control-plane object that every runtime can read before it mutates the world:

> For this action type, what proof is required, at what assurance level, bound to which real execution fields, with what replay semantics, and what evidence must be emitted afterward?

That object is the **EP Action Control Manifest**.

## Narrow-Waist Rule

Do not standardize the whole agent stack. Standardize the one invariant at the effect boundary:

```text
agent / model / runtime / MCP / A2A / HTTP / workflow
                    |
                    v
        EP Action Control Manifest
  action -> required receipt -> assurance -> execution binding -> evidence output
                    |
                    v
SCITT / WIMSE / OAuth / receipts / capsules / system-of-record adapters
```

The manifest is intentionally boring. It is a JSON control plane that says:

- which actions are consequential;
- whether a receipt is required;
- which assurance class is required (`software`, `class_a`, `quorum`);
- the enforcement point (`pre_effect_commit`);
- one-time replay semantics;
- the material fields the executor must observe from the system of record;
- the evidence profiles that must be emitted after execution;
- the conformance level the integration must pass.

## Why EMILIA Owns This Slot

EMILIA already has the pieces the manifest names:

- authorization receipt: `EP-RECEIPT-v1`;
- assurance tiers: software, Class-A device signoff, quorum;
- execution binding: observed system-of-record fields must match the signed action;
- replay refusal: one-time consumption by `receipt_id`;
- evidence output: decision log, execution attestation, reliance packet;
- conformance: `EG-1` proves missing receipt, weak assurance, drift, replay, tamper, execution proof, and reliance packet behavior.

The v0.2 manifest turns those into a public contract. It lets a maintainer, AAIF working group, SCITT implementer, WIMSE profile, or runtime vendor say:

> We do not need to adopt EMILIA's whole stack to consume its control plane. We can map our evidence object into the declared requirement and prove the effect boundary enforces it.

## Interop Mapping

| EP Action Control field | SCITT / related profile mapping |
| --- | --- |
| `action_type`, `match` | Selects the protected tool call, HTTP route, workflow step, or A2A task |
| `authorization_receipt.profile` | EP receipt, SCITT Permit, Signed Decision Receipt, or equivalent authorization evidence |
| `assurance_class` | Human-proof requirement: software-only, Class-A device-bound signoff, or quorum |
| `execution_binding.required_fields` | Fields that must be read from the system of record and bound before effect commit |
| `replay.mode` | Anti-replay / one-time consumption policy |
| `transparency.profile` | Optional registration as a SCITT Signed Statement / Transparent Statement |
| `evidence_output` | Post-execution capsule, EP execution attestation, refusal event, or reliance packet |
| `conformance.level` | Machine-testable badge that the integration really enforced the control |

## Design Boundary

The manifest does not prove a policy is wise. It does not decide who may approve. It does not replace identity, SCITT, WIMSE, OAuth, MCP, or A2A. It is the small object that tells those systems what evidence must exist before an irreversible action proceeds.

That is why it can become the glue.

## Files

- Public manifest: `public/.well-known/agent-action-control.json`
- Schema: `public/docs/schemas/agent-action-control-manifest-v0.2.schema.json`
- Validator/API: `packages/gate/action-control-manifest.js`
- Tests: `tests/action-control-manifest.test.js`
