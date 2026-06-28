# Add EMILIA in 5 minutes

Put a human's signed *yes* in front of your agent's irreversible actions — without
rewriting your stack. Pick the path that matches how your agent runs.

---

## 1. Claude Desktop / Cursor / Cline / any MCP client (0 code)
```json
{
  "mcpServers": {
    "emilia": { "command": "npx", "args": ["-y", "@emilia-protocol/mcp-server"] }
  }
}
```
Your agent can now verify receipts and require human sign-off before an irreversible
action. Public verification tools need no key; set `EP_API_KEY` for rich trust APIs
or writes.

## 2. LangChain.js (1 wrapper)
```bash
npm i @emilia-protocol/langchain
```
```js
import { withGuard } from '@emilia-protocol/langchain';

const guarded = withGuard(wireTransferTool, {
  action: 'payment.release',
  context: (input) => ({ amount: input.amount, destination: input.destination }),
  onSignoff: async (decision, input) => {
    // block until a NAMED human approves (Slack, the EP dashboard, the signoff API)
  },
});
// guarded.invoke(...) now routes through EMILIA first: allow -> run, deny -> throw,
// signoff_required -> await your approver, then run.
```
Runnable demo (offline, shows all three outcomes): `node packages/langchain/example.mjs`.

## 3. Any Node service (the demand side: require a receipt)
```bash
npm i @emilia-protocol/require-receipt
```
```js
import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';
app.post('/release', requireEmiliaReceipt({ action: 'payment.release' }), handler);
// No valid receipt -> 402 + a machine-readable challenge telling the caller how to get one.
```

## 4. Verify a receipt anywhere (offline, no account)
**JS:**
```js
import { verifyReceipt } from '@emilia-protocol/verify';
verifyReceipt(doc, signerPublicKeyBase64url); // -> { valid, checks }
```
**Python:**
```python
from emilia_verify import verify_receipt
verify_receipt(doc, signer_public_key_base64url).valid  # True/False
```

---

## What you just got
- **Pre-action enforcement:** the irreversible thing can't happen until policy passes.
- **Named human sign-off:** a signed, non-repudiable "yes" bound to the exact action.
- **A receipt:** Ed25519-signed, Merkle-anchored, verifiable offline in JS *or* Python.

Next: [`/mcp`](https://www.emiliaprotocol.ai/mcp) · the 90-second demo (`mcp-server/demo-2act.mjs`) · the EU AI Act Article 14 kit (`docs/eu-ai-act-article-14-kit.md`).
