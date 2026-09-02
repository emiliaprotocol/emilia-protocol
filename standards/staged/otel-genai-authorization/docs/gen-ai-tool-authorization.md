<!-- SPDX-License-Identifier: Apache-2.0 -->

# Semantic Conventions for GenAI tool authorization

**Status**: [Development][DocumentStatus]

Staged for `open-telemetry/semantic-conventions-genai`. Not submitted.
See [`../UPSTREAM-PR-STAGED.md`](../UPSTREAM-PR-STAGED.md).

This document is hand-written to match the shape the upstream generator
produces from
[`../model/gen-ai/authorization-registry.yaml`](../model/gen-ai/authorization-registry.yaml)
and
[`../model/gen-ai/authorization-spans.yaml`](../model/gen-ai/authorization-spans.yaml).
It has NOT been produced by, or checked against, the upstream Weaver toolchain;
see "What is unverified" below.

<!-- toc -->

- [What this group records](#what-this-group-records)
- [What this group is not](#what-this-group-is-not)
- [Attributes](#attributes)
- [Placement on spans](#placement-on-spans)
- [The query this exists for](#the-query-this-exists-for)
- [Mapping a boolean approval slot honestly](#mapping-a-boolean-approval-slot-honestly)
- [What is unverified](#what-is-unverified)

<!-- tocstop -->

## What this group records

The `execute_tool` span records the tool name, the call id, the arguments and
the result. It records nothing about whether a human authorized the call, on
what evidence, at what grade.

Every agent runtime in wide use has a human-approval slot, and in each one the
slot is a boolean: OpenAI Responses `mcp_approval_response`, the OpenAI Agents
SDK `needsApproval`, Vercel AI SDK `needsApproval`, LangChain
`HumanInTheLoopMiddleware`, Google ADK `require_confirmation`, Microsoft Agent
Framework `FunctionApprovalRequestContent`, ACP `session/request_permission`,
Claude Code `PreToolUse` `permissionDecision`. The decision is made and then
discarded. Nothing downstream can tell an approved call from an unapproved one.

This group carries the decision onto the span the runtime already emits.

## What this group is not

- **It is not an authorization.** The span observes a decision. Whether an
  approval was valid, current, in scope, or already consumed stays with the
  system that made it. A consumer MUST NOT treat these attributes as authority.
- **It is not verified.** No part of the telemetry pipeline checks
  `evidence.grade`. `independently_verifiable` means the producer says an
  artifact exists that someone else could check, and names enough to try. It
  does not mean anyone has checked it.
- **It carries no payload.** Every attribute is an enum member or a short
  opaque reference. No prompt, no argument object, no policy body, no evidence
  record, no approver identity. The convention deliberately does not standardize
  an approver identity attribute: those spans leave the producing system.

## Attributes

| Attribute | Type | Description | Examples | Requirement Level | Stability |
|---|---|---|---|---|---|
| [`gen_ai.tool.authorization.status`](#gen_aitoolauthorizationstatus) | string | The observed outcome of the authorization step for this tool call. | `authorized_in_scope`; `no_authorization_step`; `rejected` | `Opt-In` | ![Development][DevelopmentBadge] |
| [`gen_ai.tool.authorization.evidence.grade`](#gen_aitoolauthorizationevidencegrade) | string | The producer's own classification of the evidence behind the status. | `self_attested`; `independently_verifiable` | `Conditionally Required` If `status` is present. | ![Development][DevelopmentBadge] |
| `gen_ai.tool.authorization.evidence.digest` | string | Opaque content digest of the evidence artifact, `<algorithm>:<value>`. | `sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | `Conditionally Required` If grade is `independently_verifiable`. | ![Development][DevelopmentBadge] |
| `gen_ai.tool.authorization.evidence.format` | string | Media type or format identifier of that artifact. | `application/vnd.emilia.receipt.v1+json`; `application/cose` | `Conditionally Required` If grade is `independently_verifiable`. | ![Development][DevelopmentBadge] |
| `gen_ai.tool.authorization.evidence.locator` | string | Opaque producer-defined reference to where the artifact can be retrieved. | `emilia-receipt:rcp_01J8ZC4W6H` | `Conditionally Required` If grade is `independently_verifiable`. | ![Development][DevelopmentBadge] |
| `gen_ai.tool.authorization.action.digest` | string | Opaque digest of the exact action the authorization covers. | `send_payment:sha256:2c26b46b...`; `caid:v1:tool.call.1:sha256:LNJrRmj_...` | `Opt-In` | ![Development][DevelopmentBadge] |
| `gen_ai.tool.authorization.policy.digest` | string | Opaque digest of the policy in force when the decision was made. | `sha256:e3b0c44298fc1c14...` | `Opt-In` | ![Development][DevelopmentBadge] |

### `gen_ai.tool.authorization.status`

| Value | Description | Stability |
|---|---|---|
| `authorized_in_scope` | An authorization step resolved and the executed action falls inside what was authorized. | ![Development][DevelopmentBadge] |
| `authorized_out_of_scope` | An authorization step resolved, but the executed action falls outside what was authorized. | ![Development][DevelopmentBadge] |
| `authorized_without_standing` | A party authorized the call who did not hold the standing authority to authorize it. | ![Development][DevelopmentBadge] |
| `standing_preauthorization` | No per-call step ran; the call proceeded under a prior standing grant that covers it. | ![Development][DevelopmentBadge] |
| `no_authorization_step` | No authorization step existed for this call. | ![Development][DevelopmentBadge] |
| `step_bypassed` | An authorization step existed and execution was reached without completing it. | ![Development][DevelopmentBadge] |
| `auto_approved` | A non-human rule allowed the call. No human saw it. | ![Development][DevelopmentBadge] |
| `rejected` | The call was refused before execution. | ![Development][DevelopmentBadge] |
| `edited_then_approved` | A human changed the arguments and authorized the changed call. | ![Development][DevelopmentBadge] |

A `rejected` call SHOULD NOT have a successful downstream execution span for the
same `gen_ai.tool.call.id`. That invariant is the one several commenters on
[semantic-conventions-genai#95][i95] converged on independently, and it is what
lets a reader tell "blocked" apart from "never ran" and from "lost telemetry".

A step that is still pending is not a status. Producers SHOULD omit the
attribute rather than record an unresolved step as approved.

### `gen_ai.tool.authorization.evidence.grade`

| Value | Description | Stability |
|---|---|---|
| `self_attested` | The emitting runtime asserts the status. No artifact another party can re-check. | ![Development][DevelopmentBadge] |
| `third_party_logged` | A party other than the emitting runtime recorded the decision; the record is retrievable by reference. Re-reading it requires trusting that party's store. | ![Development][DevelopmentBadge] |
| `independently_verifiable` | The producer names a digest, a format and a locator for an artifact a party other than the producer can check without trusting the producer's runtime or storage. | ![Development][DevelopmentBadge] |

This attribute is the reason the group can be adopted without importing any
trust. It makes a self-attested status LOOK self-attested to the backend that
indexes it, instead of looking the same as a status someone else can check.

## Placement on spans

The group attaches to `gen_ai.execute_tool.internal`, and to the MCP
`tools/call` client and server spans, as a single `ref_group`:

```yaml
  - type: gen_ai.execute_tool.internal
    attributes:
      - ref_group: attributes.gen_ai.error
      - ref_group: attributes.gen_ai.execute_tool.common
      - ref_group: attributes.gen_ai.tool.authorization    # added
      - ref: gen_ai.operation.name
        requirement_level: required
```

`gen_ai.tool.call.id` is already the per-call anchor and is not duplicated here.

## The query this exists for

```
gen_ai.operation.name = "execute_tool"
AND gen_ai.tool.authorization.status = "no_authorization_step"
AND gen_ai.tool.risk.level IN ("high", "critical")
```

An irreversible tool call that ran with no human step. Today that question is
answered by reading code, or by inference over tool names. With this group it is
a dashboard filter over data the runtime already emits.

`gen_ai.tool.risk.level` is the producer-assessed risk band proposed separately
in [semantic-conventions-genai#373][i373]. The two proposals are complementary
and were designed that way by #373's author: risk is the assessed input that
often triggers an approval, and this group is the observed outcome of it. Either
is useful alone; together they are the query above.

## Mapping a boolean approval slot honestly

The rule that matters for producers: **do not report a value the runtime cannot
support.**

| What the runtime holds | Honest status | Honest grade |
|---|---|---|
| A boolean that was set true, no approver, no scope, no artifact | `auto_approved` | `self_attested` |
| A boolean that was set false | `rejected` | `self_attested` |
| A pending prompt no human has answered | omit the attribute | omit |
| A decision recorded by an approval service, retrievable by reference | `authorized_in_scope` | `third_party_logged` |
| A signature over a digest of this exact action, checkable by a third party | `authorized_in_scope` | `independently_verifiable` |
| A human who changed the arguments, then approved | `edited_then_approved` | as above |

`authorized_in_scope` asserts a scope. A boolean does not carry a scope, so a
producer that has only a boolean SHOULD emit `auto_approved`. That is not a
downgrade of the runtime; it is an accurate description of what the runtime
knows, and it is exactly the gap that makes the field worth having.

## What is unverified

- **The model has not been run through Weaver.** `weaver` is not installed in
  the environment where this was written and the model was not validated by the
  upstream toolchain. It was checked by (a) parsing both files as YAML, and
  (b) matching the structure key-for-key against the current upstream
  `model/gen-ai/registry.yaml` and `model/gen-ai/spans.yaml`, fetched from
  `open-telemetry/semantic-conventions-genai` at `model/manifest.yaml`
  `schema_url: https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev`. Treat
  "would validate" as unproven until Weaver has been run.
- **This markdown was not produced by the upstream generator.** Upstream docs
  are generated from the model; this file is hand-written to that shape.
- **No upstream maintainer has seen or commented on this group.** Nothing here
  has SIG standing of any kind.

[i95]: https://github.com/open-telemetry/semantic-conventions-genai/issues/95
[i373]: https://github.com/open-telemetry/semantic-conventions-genai/issues/373
[DocumentStatus]: https://opentelemetry.io/docs/specs/otel/document-status
[DevelopmentBadge]: https://img.shields.io/badge/-development-blue
