# @emilia-protocol/otel-authorization

Build the `gen_ai.tool.authorization.*` attribute map for an OpenTelemetry
`execute_tool` span from a runtime's own approval decision, and set it on a span.

Zero dependencies. `@opentelemetry/api` is an optional peer, resolved at runtime
if it is installed and ignored if it is not.

**Experimental.** The attribute group is
[staged, unsent](../../standards/staged/otel-genai-authorization/UPSTREAM-PR-STAGED.md)
for `open-telemetry/semantic-conventions-genai` issue #95. Until it is accepted
upstream, the default namespace is the vendor prefix
`emilia.tool.authorization.*`.

## What it does

Every agent runtime in wide use has a human-approval slot and every one is a
boolean. The `execute_tool` span the runtime already emits records the tool
name, the call id, the arguments and the result, and nothing about whether a
human authorized the call. This module puts that on the span.

```js
import {
  buildToolAuthorizationAttributes,
  setToolAuthorizationAttributes,
  mapMcpGuardDecision,
} from '@emilia-protocol/otel-authorization';

const mapped = mapMcpGuardDecision('allow', { irreversible: true, receipt_consumed: false });
setToolAuthorizationAttributes(span, mapped.input);
// emilia.tool.authorization.status        = "no_authorization_step"
// emilia.tool.authorization.evidence.grade = "self_attested"
```

## What it is not

- **Not an authorization.** These are span attributes: an observation the
  producer makes about its own decision. Whether an approval was valid, current,
  in scope or already consumed stays with the system that made it.
- **Not verification.** Nothing checks `evidence.grade`.
  `independently_verifiable` means the producer says an artifact exists that
  someone else could check, and names a digest, a format and a locator so they
  can try.
- **Not a payload carrier.** Every value is an enum member or a short opaque
  reference. No prompt, no argument object, no policy body, no evidence record,
  and deliberately no approver identity: these spans leave the producing system.

## The rule

**Do not report a value the runtime cannot support.**

| The runtime holds | Status | Grade |
|---|---|---|
| A boolean set true, no approver, no scope, no artifact | `auto_approved` | `self_attested` |
| A boolean set false | `rejected` | `self_attested` |
| A pending prompt no human has answered | omit | omit |
| A decision recorded by an approval service, retrievable by reference | `authorized_in_scope` | `third_party_logged` |
| A signature over a digest of this exact action | `authorized_in_scope` | `independently_verifiable` |
| A human who edited the arguments, then approved | `edited_then_approved` | as above |

## Fail-closed

Malformed, hostile or over-claiming input returns `{ ok: false, reason }` and
sets **nothing** on the span. It does not throw, does not truncate, and does not
emit a partial map. A wrong authorization status on an exported span is worse
than no status.

```js
buildToolAuthorizationAttributes({ status: 'approved', evidence_grade: 'self_attested' });
// { ok: false, reason: 'unknown_status_value' }

buildToolAuthorizationAttributes({ status: 'authorized_in_scope', evidence_grade: 'independently_verifiable' });
// { ok: false, reason: 'independently_verifiable_without_evidence_digest' }
//   NOT a silent downgrade to self_attested: that would hide a producer bug.

buildToolAuthorizationAttributes({
  status: 'rejected', evidence_grade: 'self_attested',
  evidence_digest: '{"amount":4200}',
});
// { ok: false, reason: 'evidence_digest_not_a_scoped_opaque_reference' }
```

A span whose `setAttributes` throws is reported as a telemetry refusal and never
propagates: emission cannot change an authorization outcome.

## API

- `buildToolAuthorizationAttributes(input, { namespace })` returns the validated
  attribute map or a refusal. `namespace` is `'fallback'` (default),
  `'registry'` or `'both'`.
- `setToolAuthorizationAttributes(span, input, options)` builds and writes.
  `span` may be null.
- `resolveActiveSpan()` returns the active `@opentelemetry/api` span, or null if
  the package is absent.
- `emitToolAuthorization(telemetryOptions, mapped, context)` is what the
  adapters call.
- `mapOpenAIAgentsDecision`, `mapLangGraphDecision`, `mapLangChainDecision`,
  `mapMcpGuardDecision`, `mapClaudeCodeHookDecision`.

`mapClaudeCodeHookDecision('ask')` refuses. A step handed to a human who has not
answered is not a status, and recording it as approved is the false negative the
whole group exists to expose.

## License

Apache-2.0.
