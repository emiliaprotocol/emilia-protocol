<!--
SPDX-License-Identifier: Apache-2.0
Copyright the EMILIA Protocol authors.
-->

# The "No receipt, no irreversible action" loop

**Live demo endpoint:** `POST /api/demo/require-receipt`
**Powered by:** [`@emilia-protocol/require-receipt`](../packages/require-receipt) (the demand side of the network)

This is a runnable reference for the core demand-side move: a service **refuses
to run an irreversible action unless the request arrives with a verifiable
EMILIA authorization receipt** — proof that a named human accountably authorized
*this exact action*.

It is **not auth** ("who are you") and **not permissions** ("are you allowed
here"). The receipt is *portable accountability evidence the service keeps for
its own liability*. It is the record of an authorization; it does not by itself
grant access.

The sample action this demo guards is irreversible by construction:
`demo.delete_production_database`. (Nothing is actually destroyed — it's a demo.)

---

## The loop

```
┌─────────────────────────────────────────────────────────────────┐
│  Agent wants to run an IRREVERSIBLE action                        │
└───────────────────────────────┬─────────────────────────────────┘
                                 │  POST /api/demo/require-receipt
                                 ▼
                    ┌────────────────────────┐
                    │  Receipt presented?     │
                    └──────┬──────────┬───────┘
                       no  │          │  yes
                           ▼          ▼
              402 Receipt        ┌──────────────────────┐
              Required           │ Verify (offline      │
              + challenge        │ Ed25519, canonical   │
              "here is exactly   │ JSON): bound to this  │
               what to bring"    │ action? fresh?        │
                           │     │ acceptable outcome?   │
                           │     └──────┬─────────┬──────┘
                           │       no   │         │  yes
                           │            ▼         ▼
                           │      402 + reason   200 OK
                           │      (rejected:{})  action runs;
                           │                     service keeps
                           ▼                     the receipt as
              Agent obtains a receipt            its accountability
              and RETRIES  ◄────────────────────  evidence
```

A well-behaved agent treats the `402` like a browser treats `401`: it reads the
machine-readable challenge, obtains a receipt bound to the named action, and
retries — **no human in the loop**. That is why the demand side is self-adopting.

`402` deliberately aligns with the emerging "challenge-to-transact" convention
for agent commerce (x402 / AP2): receipts ride the same rail payments do.

---

## Verification semantics

The demo verifies receipts with `allowInlineKey: true` — it accepts a
**self-signed** EP-RECEIPT-v1 document so anyone can drive the loop end to end.
That proves the receipt was **not tampered with**; it does **not** mean EMILIA
vouches for the issuer.

In production the verifier instead **pins the trusted issuer keys** it will
accept (for example from `/.well-known/ep-keys.json`) and passes them as
`trustedKeys`. Every fact the endpoint returns (`receipt_id`, `subject`,
`outcome`, `signer`) is something the caller can independently re-derive by
verifying the same receipt offline — no EMILIA-vouched opinion or score is
involved.

The endpoint requires the receipt to be:

- **bound to the action** — `claim.action_type === "demo.delete_production_database"`
- **fresh** — `created_at` within `maxAgeSec` (900s)
- **an acceptable outcome** — `allow` or `allow_with_signoff`

Privacy: the endpoint never echoes your raw action parameters or the full
receipt payload — only the non-sensitive verification facts an integrator would
log.

---

## Try it with curl

### 1. No receipt → `402 EMILIA Receipt Required`

```bash
curl -i -X POST http://localhost:3000/api/demo/require-receipt
```

Response (truncated):

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: EMILIA realm="agent-actions", action="demo.delete_production_database"
Content-Type: application/json

{
  "type": "https://emiliaprotocol.ai/errors/emilia_receipt_required",
  "title": "EMILIA Receipt Required",
  "status": 402,
  "detail": "Refusing an irreversible action: no EMILIA authorization receipt was presented.",
  "required": {
    "action": "demo.delete_production_database",
    "header": "X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)",
    "how": "Obtain a receipt (run emilia-gate, the SDK, or POST /api/trust/gate), then resend with the header.",
    "learn_more": "https://www.emiliaprotocol.ai/agent-guard"
  },
  "loop": {
    "rule": "No receipt, no irreversible action.",
    "sample_action": "demo.delete_production_database",
    "why": "This action cannot be undone. The service requires portable, verifiable proof that a named human accountably authorized THIS exact action before it will run...",
    "to_proceed": [ "...", "..." ]
  }
}
```

### 2. Invalid receipt → `402` with the rejection reason

Send a receipt that is malformed, expired, or bound to the wrong action:

```bash
curl -i -X POST http://localhost:3000/api/demo/require-receipt \
  -H 'Content-Type: application/json' \
  -d '{"emilia_receipt":{"@version":"EP-RECEIPT-v1","payload":{"claim":{"action_type":"some.other.action"}},"signature":{"value":"AAAA"}}}'
```

Response (truncated):

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: EMILIA realm="agent-actions", action="demo.delete_production_database"

{
  "title": "EMILIA Receipt Required",
  "status": 402,
  "detail": "Refusing an irreversible action: receipt rejected (untrusted_or_invalid_signature).",
  "rejected": { "ok": false, "reason": "untrusted_or_invalid_signature" }
}
```

Possible `rejected.reason` values: `malformed_receipt`,
`bad_signature_encoding`, `untrusted_or_invalid_signature`, `receipt_expired`,
`action_mismatch`, `outcome_not_accepted`.

### 3. Valid receipt → `200`

Present a valid EP-RECEIPT-v1 document bound to
`demo.delete_production_database`. You can produce one with the SDK or
`emilia-gate`; this demo accepts a self-signed receipt (`allowInlineKey`).

```bash
# RECEIPT_B64 = base64 of an EP-RECEIPT-v1 JSON document
curl -i -X POST http://localhost:3000/api/demo/require-receipt \
  -H "X-EMILIA-Receipt: $RECEIPT_B64"
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": 200,
  "allowed": true,
  "action": "demo.delete_production_database",
  "note": "Demo only — no data was destroyed. With a valid receipt the irreversible action would run, and the service would keep this receipt as its own portable accountability evidence.",
  "evidence": {
    "receipt_id": "...",
    "subject": "...",
    "outcome": "allow",
    "signer": "MCowBQYDK2Vw…"
  }
}
```

### See the loop description (GET)

```bash
curl -s http://localhost:3000/api/demo/require-receipt | jq
```

---

## Drop it in front of your own action

```js
import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';

app.post(
  '/delete-account',
  requireEmiliaReceipt({
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY], // base64url SPKI you trust
    action: 'account.delete',
    maxAgeSec: 900,
  }),
  (req, res) => {
    // Only reached with a fresh, untampered, action-bound receipt from a
    // trusted issuer. req.emiliaReceipt holds the verified claim — keep it.
    res.json({ deleted: true, receipt: req.emiliaReceipt.receipt_id });
  },
);
```

A guardrail blocks *your* agent (a cost). A required receipt makes *every*
counterparty demand portable proof of accountable authorization. See
[/agent-guard](https://www.emiliaprotocol.ai/agent-guard) and the package
[README](../packages/require-receipt/README.md).

Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
