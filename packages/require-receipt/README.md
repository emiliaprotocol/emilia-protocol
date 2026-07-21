# @emilia-protocol/require-receipt

**The demand side of the EMILIA network.** One line that lets any service refuse
an irreversible agent action unless it arrives with a verifiable Trust Receipt —
proof that a named human accountably authorized *this exact action*.

This is **not auth** ("who are you") and **not permissions** ("are you allowed
here"). It's *portable accountability evidence the service keeps for its own
liability* — and the thing that makes agents adopt EMILIA on their own.

> **Scope of what this enforces.** `require-receipt` verifies the receipt's
> signature, freshness, assurance tier, and action binding. Exact parameter
> binding is available only when the relying service supplies its real
> system-of-record action, action hash, required fields, and CAID selector. A
> middleware configured with only `action` proves only that the trusted issuer
> signed that action type. Use `@emilia-protocol/gate` or the edge handler below
> for the full reserve-before-effect and one-use consequence boundary.

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
    manifestUrl: '/.well-known/agent-action-control.json',
    authorization: {
      authorization_endpoint: 'https://approve.example.com/api/v1/approvals',
      flow: 'EP-APPROVAL-v1',
    },
    requiredFields: ['action_type', 'amount', 'currency', 'beneficiary_account_hash'],
    maxAgeSec: 900,
  }),
  (req, res) => {
    // Only reached if a fresh, untampered receipt from a trusted issuer, bound
    // to this action_type, was presented. req.emiliaReceipt holds the verified
    // claim. Parameter-level binding (amount/beneficiary/…) is the Gate's job —
    // see the scope note above.
    res.json({ released: true, receipt: req.emiliaReceipt.receipt_id });
  },
);
```

## Receipt Required loop (why agents self-adopt)

No receipt? The service answers **`428 Precondition Required`** with a
`Receipt-Required` challenge telling the agent exactly what to bring. An
already-provisioned client holding the separately issued requester credential
can obtain one and retry without a support ticket. Credential provisioning is
outside EP-APPROVAL-v1. Existing callers may omit `statusCode` to keep the
original 402/x402-compatible shape.

```
→ POST /release-payment            (no receipt)
← 428 EMILIA Receipt Required
  Receipt-Required: action="payment.release", proof="X-EMILIA-Receipt",
                    manifest="/.well-known/agent-action-control.json",
                    authorization_endpoint="https://approve.example.com/api/v1/approvals",
                    flow="EP-APPROVAL-v1", profile="EP-RECEIPT-v1"

→ POST the exact challenged action to the pinned authorization endpoint
← 201 { request_id, approval_url, poll_token, status: "pending", expires_at }

→ GET /api/v1/approvals/{request_id}   Authorization: EP-Approval {poll_token}
← 200 { request_id, status: "approved", receipt: { ... } }

→ POST /release-payment            X-EMILIA-Receipt: base64(<receipt>)
← 200 { released: true }
```

`428` is the clean HTTP precondition rail for "bring an authorization receipt
before mutation." `402` remains useful when deliberately composing with x402/AP2
agent-commerce flows.

The endpoint named by a challenge is **discovery, not a trust root**. An agent
must match it against an endpoint obtained out of band before sending action
data or polling. `beginReceiptApproval` and `pollReceiptApproval` enforce that
pin and never follow redirects.

The EMILIA-hosted reference server currently advertises acquisition only for
the closed `payment.release` Class-A profile (across its MCP and HTTP
descriptors). Other receipt-required actions remain challenge-only. Services
must not publish an `authorization` descriptor until their server has a real
profile and terminal evidence path for that action.

```js
import { beginReceiptApproval, pollReceiptApproval } from '@emilia-protocol/require-receipt';

const pending = await beginReceiptApproval({
  authorization: challenge.required.authorization,
  trustedAuthorization: configuredApprovalEndpoint,
  challenge: challenge.required,
  action: exactSystemOfRecordAction,
  approver_id: 'approver@example.com',
  idempotency_key: crypto.randomUUID(),
  // Injected from the requester's own secret store. It is never accepted from
  // the challenge or manifest.
  requesterAuthorization: () => `Bearer ${process.env.EMILIA_API_KEY}`,
});

const result = await pollReceiptApproval({
  authorization: challenge.required.authorization,
  trustedAuthorization: configuredApprovalEndpoint,
  request_id: pending.request_id,
  poll_token: pending.poll_token,
});
```

## Action Control Manifest v0.2

Services publish the current machine-readable contract at
`/.well-known/agent-action-control.json`. The legacy Action Risk v0.1 manifest
remains readable for compatibility but does not carry acquisition metadata.

```json
{
  "@version": "EP-ACTION-CONTROL-MANIFEST-v0.2",
  "actions": [
    {
      "id": "mcp.release_payment",
      "match": { "protocol": "mcp", "tool": "release_payment" },
      "action_type": "payment.release",
      "risk": "high",
      "receipt_required": true,
      "assurance_class": "class_a",
      "control": {
        "execution_binding": {
          "required": true,
          "source": "system_of_record",
          "required_fields": ["action_type", "amount", "currency", "beneficiary_account_hash", "action_caid"],
          "caid_selector": { "field": "action_caid" }
        },
        "authorization": {
          "authorization_endpoint": "https://approve.example.com/api/v1/approvals",
          "flow": "EP-APPROVAL-v1"
        }
      }
    }
  ]
}
```

Validate and resolve Action Control entries with `@emilia-protocol/gate`. The
older `validateActionRiskManifest` and `findActionRequirement` helpers remain
available for v0.1 consumers.

## Zero-code-change edge enforcement

```js
import { createReceiptRequiredEdgeHandler } from '@emilia-protocol/require-receipt/edge';
```

The runtime-neutral edge handler produces strict RFC 7807 challenges, strips
the receipt before forwarding, and can atomically consume one-use receipt IDs.
Deployable Cloudflare Worker, Envoy, nginx, Node, and PostgreSQL reference
configurations live in `examples/receipt-required-gateways`. For irreversible
effects, `consume` must be a durable atomic insert-if-absent; verification-only
mode is not a one-use consequence boundary.

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
