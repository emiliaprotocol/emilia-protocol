# @emilia-protocol/langchain

**Guard LangChain.js tools with EMILIA Protocol.** Wrap any high-risk tool so the
agent can't take an irreversible action until EMILIA says it's safe — or a named
human signs off. Every decision can produce a verifiable
[Trust Receipt](https://www.emiliaprotocol.ai/spec).

```bash
npm install @emilia-protocol/langchain
```

## Wrap a tool

```js
import { withGuard } from '@emilia-protocol/langchain';
import { DynamicStructuredTool } from '@langchain/core/tools';
import { z } from 'zod';

const wireMoney = new DynamicStructuredTool({
  name: 'wire_money',
  description: 'Release a wire transfer',
  schema: z.object({ amount: z.number(), to: z.string() }),
  func: async ({ amount, to }) => bank.wire(amount, to),
});

// One wrap. The tool now refuses to run until EMILIA allows it.
const guarded = withGuard(wireMoney, {
  action: 'payment.release',
  context: (input) => ({ amount: input.amount, destination: input.to }),
  // Optional: resolve once a human approves (otherwise signoff throws).
  onSignoff: async (decision) => waitForApproval(decision.raw),
});

// Give `guarded` to your agent instead of `wireMoney`.
await guarded.invoke({ amount: 50000, to: 'acct_9f12' });
// → throws "EMILIA requires human signoff for \"payment.release\"" until approved
```

## Low-level: just ask the gate

```js
import { guardAction } from '@emilia-protocol/langchain';

const d = await guardAction({
  actor: 'invoice_bot',
  action: 'payment.release',
  context: { amount: 50000 },
});
// { allow, deny, signoffRequired, reason, raw }
if (d.deny) throw new Error('blocked');
```

## API

### `withGuard(tool, opts)`
Returns a proxy of `tool` whose `.invoke()` is gated. Preserves `name`,
`description`, `schema`, and identity.

| opt | type | required | notes |
|-----|------|----------|-------|
| `action` | string | yes | canonical action name, e.g. `payment.release` |
| `actor` | string | no | defaults to the tool's `name` |
| `context` | object \| `(input) => object` | no | action context sent to the gate |
| `onSignoff` | `(decision, input) => Promise<void>` | no | resolve when a human approves; if omitted, signoff throws |
| `gateUrl` | string | no | defaults to the public EMILIA gate |
| `fetchImpl` | fetch | no | inject a fetch (tests / non-global environments) |

### `guardAction(opts)`
Returns `{ allow, deny, signoffRequired, reason, raw }`.

## Other frameworks

`withGuard` works with anything exposing `.invoke(input)`. For CrewAI (Python),
AutoGPT, or a custom loop, call the same gate directly — see
[/agent-guard](https://www.emiliaprotocol.ai/agent-guard).

Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
