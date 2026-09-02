<!-- SPDX-License-Identifier: Apache-2.0 -->

# `gen_ai.tool.authorization.*` for OpenTelemetry GenAI semantic conventions

An attribute group for the `execute_tool` span, recording whether an
authorization step resolved for a tool call, on what class of evidence, and
against which action and policy.

**Status: staged, unsent.** Nothing here has been submitted to, posted in, or
discussed with `open-telemetry/semantic-conventions-genai` or any other upstream
repository. See [`UPSTREAM-PR-STAGED.md`](UPSTREAM-PR-STAGED.md).

## The gap

The `execute_tool` span records the tool name, the call id, the arguments and
the result. It records nothing about whether a human authorized the call.

Every agent runtime in wide use has a human-approval slot and every one of them
is a boolean. The decision is made, the run resumes, and the decision is gone.
Downstream, an approved call and an unapproved one are the same span.

The `gen_ai` attribute registry has 72 attributes. None of them names a human,
an approval, an authorization, a consent, a permission or a policy. Checked
against `model/gen-ai/registry.yaml` on 2026-09-02.

## Contents

| Path | What it is |
|---|---|
| `model/gen-ai/authorization-registry.yaml` | The attribute definitions, in the upstream `definition/2` registry format |
| `model/gen-ai/authorization-spans.yaml` | The attribute group and its one-line attachment to `gen_ai.execute_tool.internal` |
| `docs/gen-ai-tool-authorization.md` | Documentation in the shape the upstream generator produces. Hand-written, NOT generated |
| `CROSSWALK.md` | How this composes with semconv-genai #95, #239, #373, #159, #132 and Traceloop RFC #3460, quoted literally with URLs; plus the crosswalk onto EMILIA's own two shipped vocabularies, which use different value names |
| `UPSTREAM-PR-STAGED.md` | The contribution as it would be submitted, the draft #95 comment, and the gate list of what must be true first |
| `examples/run.mjs` | Worked examples driving the real adapters with real signed receipts |
| `examples/OUTPUT.txt` | The recorded output of an actual run |
| `collector/authorization-presence-processor.yaml` | An OpenTelemetry Collector config turning the convention into an operational control |

## The emitters

`packages/otel-authorization` builds and validates the attribute map. It has
zero dependencies and never imports `@opentelemetry/api` statically; the package
is an optional peer, resolved at runtime if present.

Four adapters emit the group, opt-in per adapter:

| Adapter | Option | Emits onto |
|---|---|---|
| `packages/openai-agents` | `otelAuthorization` | a span you pass, or the active `@opentelemetry/api` span |
| `packages/langgraph` | `otelAuthorization` | same |
| `packages/langchain` | `otelAuthorization` | same |
| `packages/mcp-guard` | `otelAuthorization` | same |
| `integrations/claude-code-plugin` | `EP_OTEL_AUTHORIZATION=1` | **cannot set span attributes.** A PreToolUse hook is a separate process with no handle on the host's span. It writes the same attribute map as one structured stderr line instead |

Default namespace is the vendor prefix `emilia.tool.authorization.*`. The
registry names are opt-in and stay that way unless the group is accepted
upstream, because an attribute outside the registry is invisible to every
consumer that has not been told about it.

## The rule the emitters follow

**Do not report a value the runtime cannot support.**

A boolean approval slot with no approver, no scope and no artifact supports
`auto_approved` and `rejected`. It does not support `authorized_in_scope`, which
asserts a scope the boolean never carried. A pending prompt no human has answered
is not a status at all and the attribute is omitted.

`packages/otel-authorization` enforces this by refusing rather than guessing.
`independently_verifiable` without a digest, a format and a locator is a
refusal, not a silent downgrade, because a silent downgrade would hide a
producer bug in the data.

## Run it

```
node standards/staged/otel-genai-authorization/examples/run.mjs
npx vitest run tests/otel-tool-authorization.test.ts
```

## What this does not claim

- It does not make authorization verifiable. It makes the absence of
  authorization queryable.
- `evidence.grade` is a producer claim. Nothing in the telemetry path checks it.
  `independently_verifiable` means the producer says an artifact exists that
  someone else could check, and names enough to try.
- The compelled read here is ingestion by observability backends. Ingestion is
  not verification, and no consumer is compelled to verify anything.
- No OpenTelemetry maintainer has seen this. It has no SIG standing of any kind.
