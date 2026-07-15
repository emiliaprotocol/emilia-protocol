<!-- SPDX-License-Identifier: Apache-2.0 -->
# Add Receipt Required to an MCP server in 10 minutes

Receipt Required is the adoption rail for irreversible agent tools:

```text
agent calls dangerous MCP tool
server returns 428 Receipt Required
agent obtains an EP-RECEIPT-v1 bound to the exact action
server verifies offline, consumes before mutation, then runs the tool
same receipt again is replay-refused
```

The pitch is intentionally small:

> No receipt, no irreversible action.

## 1. Publish an Action Risk Manifest

Put this at `/.well-known/agent-actions.json`. Start with one dangerous tool.

```json
{
  "@version": "EP-ACTION-RISK-MANIFEST-v0.1",
  "service": {
    "name": "Acme MCP",
    "manifest_url": "https://mcp.example.com/.well-known/agent-actions.json"
  },
  "receipt_required": {
    "status": 428,
    "challenge_header": "Receipt-Required",
    "proof_header": "X-EMILIA-Receipt",
    "receipt_profile": "EP-RECEIPT-v1"
  },
  "defaults": {
    "read_only": "allow",
    "missing_receipt": "refuse",
    "invalid_receipt": "refuse",
    "stale_receipt": "refuse"
  },
  "actions": [
    {
      "id": "mcp.release_payment",
      "match": { "protocol": "mcp", "tool": "release_payment" },
      "action_type": "payment.release",
      "risk": "high",
      "receipt_required": true,
      "assurance_class": "class_a",
      "max_age_sec": 900,
      "quorum": { "required": false }
    }
  ]
}
```

The manifest does not grant permission. It is a refusal contract: which action
requires proof, and what proof the caller must bring.

## 2. Wrap the dispatcher

Install the demand-side verifier:

```bash
npm i @emilia-protocol/require-receipt
```

Then resolve the current tool from the manifest and fail closed before the
mutation.

```js
import {
  findActionRequirement,
  makeReceiptGate,
} from '@emilia-protocol/require-receipt';

const manifest = await fetch('https://mcp.example.com/.well-known/agent-actions.json')
  .then((r) => r.json());
const gates = new Map();
const approverKeys = JSON.parse(process.env.EMILIA_APPROVER_KEYS_JSON);
const allowedOrigins = process.env.EMILIA_ALLOWED_ORIGINS.split(',');

// Inject a fleet-wide ownership-fenced implementation. reserve() must be an
// atomic insert-if-absent; an uncertain reservation remains closed.
const store = productionReceiptStore; // { reserve, commit, release }

function gateFor(req) {
  if (!gates.has(req.action_type)) {
    gates.set(req.action_type, makeReceiptGate({
      action: req.action_type,
      trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY].filter(Boolean),
      approverKeys,
      rpId: process.env.EMILIA_RP_ID,
      allowedOrigins,
      assuranceClass: req.assurance_class,
      quorum: req.quorum,
      quorumPolicy: req.quorum?.required ? PINNED_QUORUM_POLICIES[req.id] : undefined,
      maxAgeSec: req.max_age_sec,
      manifestUrl: '/.well-known/agent-actions.json',
      store,
    }));
  }
  return gates.get(req.action_type);
}

function stripEpControlArgs(args = {}) {
  const { __ep, emilia_receipt, ...clean } = args;
  return clean;
}

export async function guardedCallTool(name, args, extra = {}) {
  const req = findActionRequirement(manifest, { protocol: 'mcp', tool: name });
  if (!req?.receipt_required) return handleTool(name, args, extra);

  const receipt = args.__ep?.receipt || args.emilia_receipt || extra._meta?.emilia_receipt;
  const clean = stripEpControlArgs(args);
  const result = await gateFor(req).run(
    receipt,
    { target: clean.payment_id },
    () => handleTool(name, clean, extra),
  );
  return result.ok ? result.result : result.body;
}
```

`productionReceiptStore` must implement atomic, ownership-fenced
`{ reserve, commit, release }` operations. The gate verifies issuer trust,
WebAuthn assurance under the relying party's approver directory and RP/origin
scope, exact target binding, and one-time consumption before invoking the tool.

## 3. Prove it cold

Run the repo examples with no account, API key, or EMILIA server:

```bash
FAST=1 node examples/mcp/payment-server.mjs
FAST=1 node examples/mcp/github-admin.mjs
FAST=1 node examples/mcp/prod-deploy.mjs
```

Each demo proves four things:

1. No receipt returns `428 Receipt Required`.
2. A named human signs the exact action and the tool runs.
3. The same receipt presented again is refused as `replay_refused`.
4. A tampered receipt is refused before mutation.

## 4. Go live with consume-before-write

For system-of-record enforcement, use `withMcpReceiptGuard` from
`@emilia-protocol/mcp-guard` with the SDK. It drives the live v1 flow:
require receipt, request signoff if needed, consume before mutation, run the
tool, then emit execution evidence.

```js
import { EPClient } from '@emilia-protocol/sdk';
import { withMcpReceiptGuard } from '@emilia-protocol/mcp-guard';

const ep = new EPClient({ apiKey: process.env.EP_API_KEY });

const guardedHandleTool = withMcpReceiptGuard(handleTool, {
  client: ep,
  executingSystem: 'acme-mcp-server',
  annotations: {
    release_payment: {
      irreversible: true,
      actionType: 'payment.release',
      targetResourceId: (args) => args.payment_id,
      amount: (args) => args.amount,
      currency: (args) => args.currency,
      approverId: 'ap_controller_jane',
      onSignoffRequired: async ({ signoff }) => waitForApprovedSignoff(signoff.signoff_id),
    },
  },
});
```

If consume fails, your `handleTool` function is never called.

## HTTP services

For ordinary APIs, use the same 428 rail with
`@emilia-protocol/require-receipt`:

```js
import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';

app.post(
  '/release-payment',
  requireEmiliaReceipt({
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY],
    action: 'payment.release',
    statusCode: 428,
    manifestUrl: '/.well-known/agent-actions.json',
    maxAgeSec: 900,
  }),
  (req, res) => res.json({ released: true, receipt: req.emiliaReceipt.receipt_id }),
);
```

Omit `statusCode` only when you deliberately need the legacy 402/x402-compatible
shape.

## The test

An integration passes the Receipt Required test when this sentence is
mechanically true:

> If an agent changes money, code, permissions, records, or regulated state
> without a valid EMILIA receipt, the system rejects it; if it proceeds, the
> receipt proves exactly who authorized exactly what under exactly which policy.
