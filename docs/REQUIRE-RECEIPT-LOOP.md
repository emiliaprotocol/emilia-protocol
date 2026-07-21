<!--
SPDX-License-Identifier: Apache-2.0
Copyright the EMILIA Protocol authors.
-->

# The "No receipt, no irreversible action" loop

**Live demo endpoint:** `POST /api/demo/require-receipt`
**Powered by:** [`@emilia-protocol/require-receipt`](../packages/require-receipt)
**HTTP conformance:** [`tests/http-api-conformance.test.ts`](../tests/http-api-conformance.test.ts)

EMILIA makes agent accountability verifiable. Before an agent changes money,
code, permissions, records, or regulated state, the system requires a receipt.
If the action runs, anyone can verify who approved exactly what, under which
policy, without trusting EMILIA's server.

This is **not auth** ("who are you") and **not permissions** ("are you allowed
here"). The receipt is portable accountability evidence the service keeps: proof
that a named human or quorum authorized this exact action, under the policy in
force, before the mutation reached the system of record.

The public demo guards three concrete actions:

- `release_funds` -> `payment.release:wire:vendor-acme-250000`
- `delete_repo` -> `github.repo.delete:repo:emilia/prod-ledger`
- `change_bank_account` -> `payment.bank_details.change:vendor:acme-routing-9124`

Nothing is actually mutated. The route simulates the mutation and exports the
evidence packet an integrator would retain.

---

## The HTTP-RR-1 Sequence

```text
Agent calls a consequential endpoint
        |
        v
Missing receipt?
        |
        +-- yes -> HTTP 428 Receipt Required
        |          Receipt-Required: action="payment.release:wire:..."
        |          JSON body explains the exact receipt to bring
        |
        +-- no  -> Verify receipt offline:
                   - Ed25519 canonical JSON signature
                   - exact action binding
                   - acceptable outcome
                   - freshness
                   - one-time consumption
                   - trusted issuer keys in production
                         |
                         +-- fail -> HTTP 428 + sanitized rejection reason
                         |
                         +-- pass -> mutation runs, receipt is consumed once,
                                     evidence_packet is exported
```

The conformance test proves the API boundary, not just the verifier library:

1. Missing receipt returns `428 Receipt Required`.
2. A receipt bound to the exact action runs.
3. The same receipt replay is refused.
4. A tampered receipt is refused.
5. The successful response exports an evidence packet.

Run it:

```bash
npx vitest run tests/http-api-conformance.test.ts
```

---

## Try It

### 1. No receipt -> `428 Receipt Required`

```bash
curl -i -X POST http://localhost:3000/api/demo/require-receipt \
  -H 'Content-Type: application/json' \
  -d '{"demo":"release_funds"}'
```

Response shape:

```http
HTTP/1.1 428 Precondition Required
Receipt-Required: action="payment.release:wire:vendor-acme-250000", manifest="/.well-known/agent-actions.json", proof="X-EMILIA-Receipt", profile="EP-RECEIPT-v1", assurance="class_a", max_age="900"
Content-Type: application/json
```

```json
{
  "title": "EMILIA Receipt Required",
  "status": 428,
  "required": {
    "action": "payment.release:wire:vendor-acme-250000",
    "proof_header": "X-EMILIA-Receipt"
  },
  "loop": {
    "invariant": "No receipt, no irreversible action.",
    "product": "EMILIA makes agent accountability verifiable."
  }
}
```

### 2. Valid receipt -> `200` + evidence packet

Present an EP-RECEIPT-v1 document bound to the exact demo action:

```bash
curl -i -X POST http://localhost:3000/api/demo/require-receipt \
  -H 'Content-Type: application/json' \
  -d '{"demo":"release_funds","emilia_receipt":{...}}'
```

Response shape:

```json
{
  "status": 200,
  "allowed": true,
  "action": "payment.release:wire:vendor-acme-250000",
  "evidence": {
    "receipt_id": "rcpt_...",
    "outcome": "allow_with_signoff",
    "signer": "MCowBQYDK2Vw..."
  },
  "evidence_packet": {
    "@version": "EP-DEMO-EVIDENCE-v1",
    "authorized_action": "payment.release:wire:vendor-acme-250000",
    "policy_id": "demo.payment-release.class-a.v1",
    "checks": [
      "missing_receipt_refuses_428",
      "exact_action_receipt_verifies_offline",
      "receipt_consumed_once",
      "replay_refused",
      "tamper_refused"
    ]
  }
}
```

### 3. Replay -> `428 replay_refused`

Send the same receipt again. It fails because the gate has already consumed the
receipt once.

### 4. Tamper -> `428 untrusted_or_invalid_signature`

Change the payload after signature. It fails because the canonical JSON bytes no
longer match the Ed25519 signature.

---

## Production Notes

The public demo accepts inline, self-signed keys so anyone can run the loop
without an EMILIA account. That proves integrity only. Production deployments
pin trusted issuer keys, usually discovered from `/.well-known/ep-keys.json` or
configured out-of-band.

For x402/AP2-compatible flows that deliberately need the legacy commercial
challenge shape, the library still supports `402`. New Receipt Required rails
SHOULD use `428 Precondition Required`.

Apache-2.0 - part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
