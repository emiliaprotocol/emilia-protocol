# @emilia-protocol/require-receipt

**The demand side of the EMILIA network.** One line that lets any service refuse
an irreversible agent action unless it arrives with a verifiable Trust Receipt —
proof that a named human accountably authorized *this exact action*.

This is **not auth** ("who are you") and **not permissions** ("are you allowed
here"). It's *portable accountability evidence the service keeps for its own
liability* — and the thing that makes agents adopt EMILIA on their own.

```bash
npm install @emilia-protocol/require-receipt
```

## Require a receipt (Express / Connect / Next route handler)

```js
import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';

app.post(
  '/release-payment',
  requireEmiliaReceipt({
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY], // base64url SPKI you trust
    action: 'payment.release',
    statusCode: 428, // new Receipt Required rail; omit for legacy 402 compatibility
    manifestUrl: '/.well-known/agent-actions.json',
    maxAgeSec: 900,
  }),
  (req, res) => {
    // Only reached if a fresh, untampered, action-bound receipt from a trusted
    // issuer was presented. req.emiliaReceipt holds the verified claim.
    res.json({ released: true, receipt: req.emiliaReceipt.receipt_id });
  },
);
```

## Receipt Required loop (why agents self-adopt)

No receipt? The service answers **`428 Precondition Required`** with a
`Receipt-Required` challenge telling the agent exactly what to bring — so a
well-behaved agent obtains one and retries, no support ticket needed. Existing
callers may omit `statusCode` to keep the original 402/x402-compatible shape.

```
→ POST /release-payment            (no receipt)
← 428 EMILIA Receipt Required
  Receipt-Required: action="payment.release", proof="X-EMILIA-Receipt",
                    manifest="/.well-known/agent-actions.json", profile="EP-RECEIPT-v1"
  { required: { action: "payment.release", header: "X-EMILIA-Receipt: base64(...)", how: "..." } }

→ POST /release-payment            X-EMILIA-Receipt: base64(<receipt>)
← 200 { released: true }
```

`428` is the clean HTTP precondition rail for "bring an authorization receipt
before mutation." `402` remains useful when deliberately composing with x402/AP2
agent-commerce flows.

## Action Risk Manifest

Services can publish the risk contract agents should honor at
`/.well-known/agent-actions.json`:

```json
{
  "@version": "EP-ACTION-RISK-MANIFEST-v0.1",
  "actions": [
    {
      "id": "mcp.release_payment",
      "match": { "protocol": "mcp", "tool": "release_payment" },
      "action_type": "payment.release",
      "risk": "high",
      "receipt_required": true,
      "assurance_class": "class_a"
    }
  ]
}
```

Validate and resolve entries with the package helpers:

```js
import { validateActionRiskManifest, findActionRequirement } from '@emilia-protocol/require-receipt';

const check = validateActionRiskManifest(manifest);
if (!check.ok) throw new Error(check.errors.join('\\n'));

const requirement = findActionRequirement(manifest, { protocol: 'mcp', tool: 'release_payment' });
```

## Just verify (no framework)

```js
import { verifyEmiliaReceipt } from '@emilia-protocol/require-receipt';

const v = verifyEmiliaReceipt(receiptDoc, {
  trustedKeys: [issuerPubKey],
  action: 'payment.release',
  maxAgeSec: 900,
});
// { ok, reason?, outcome?, subject?, receipt_id?, signer? }
```

Offline Ed25519 over canonical JSON — same shape as
[`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify).
No network. You pin the issuers you trust.

## Why this is the moat, not the gate
A guardrail blocks *your* agent (a cost). A required receipt makes *every*
counterparty demand portable proof — and the more that demand it, the less choice
any agent has but to issue one. EMILIA becomes the issuer and verifier of record
for accountable agent action. See [/agent-guard](https://www.emiliaprotocol.ai/agent-guard).

Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
