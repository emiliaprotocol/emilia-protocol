<!-- SPDX-License-Identifier: Apache-2.0 -->
# Receipt Required v0.2

Receipt Required is the additive challenge-response rail for irreversible agent
actions:

```text
agent attempts irreversible action
service returns Receipt Required
agent follows a pinned EP-APPROVAL-v1 acquisition endpoint
named human reviews the exact action and approves or denies
agent polls with a separate private capability and obtains an EP-RECEIPT-v1
agent retries with the receipt
service verifies offline, consumes if applicable, then executes
```

It does not rename EP Core and it does not replace authorization receipts. It is
the small protocol moment that lets services say:

> No receipt, no irreversible action.

**Conformance & badge:** the ritual is testable — see
[RECEIPT-REQUIRED-CONFORMANCE.md](RECEIPT-REQUIRED-CONFORMANCE.md) for the
backward-compatible RR-1 level and the stricter RR-2 acquisition profile.

## HTTP profile

New integrations SHOULD use HTTP `428 Precondition Required` when the missing
precondition is an authorization receipt.

```http
HTTP/1.1 428 Precondition Required
Content-Type: application/problem+json
Receipt-Required: action="payment.release", action_hash="sha256:…", proof="X-EMILIA-Receipt", manifest="/.well-known/agent-action-control.json", profile="EP-RECEIPT-v1", assurance="class_a", authorization_endpoint="https://authorize.example/v1/approvals", flow="EP-APPROVAL-v1", required_fields="[\"action_type\",\"amount\",\"currency\",\"beneficiary_account_hash\"]", max_age="900"
```

The response body is an RFC 7807-style problem object:

```json
{
  "type": "https://emiliaprotocol.ai/errors/emilia_receipt_required",
  "title": "EMILIA Receipt Required",
  "status": 428,
  "detail": "No EMILIA receipt presented.",
  "required": {
    "action": "payment.release",
    "action_hash": "sha256:…",
    "manifest": "/.well-known/agent-action-control.json",
    "challenge_header": "Receipt-Required",
    "proof_header": "X-EMILIA-Receipt",
    "header": "X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)",
    "assurance_class": "class_a",
    "max_age_sec": 900,
    "authorization": {
      "authorization_endpoint": "https://authorize.example/v1/approvals",
      "flow": "EP-APPROVAL-v1"
    },
    "required_fields": ["action_type", "amount", "currency", "beneficiary_account_hash"],
    "caid_selector": { "field": "action_caid" }
  }
}
```

Existing EMILIA demand-loop demos and x402-compatible flows MAY continue to use
HTTP `402` for compatibility. The semantics are the same: the action is refused
until the caller presents a valid authorization receipt.

## Action Control Manifest

A service publishes its risk contract at:

```text
/.well-known/agent-action-control.json
```

The deployed control manifest is `EP-ACTION-CONTROL-MANIFEST-v0.2`. It tells
agents, MCP clients, auditors, and test harnesses which actions are guarded,
which material fields must bind, and—when the acquisition extension is
present—where an already-trusted client can request the receipt. The legacy
`/.well-known/agent-actions.json` v0.1 document remains available for older
clients; it is not the acquisition contract.

Required top-level fields:

| Field | Meaning |
|---|---|
| `@version` | Must be `EP-ACTION-CONTROL-MANIFEST-v0.2`. |
| `service` | Service metadata, issuer, and canonical manifest URL. |
| `defaults` | Default behavior for read-only, missing, invalid, or stale receipts. |
| `evidence_profiles` | Receipt, execution-attestation, reliance, and transparency profiles. |
| `actions` | List of action requirements. |

Each action entry has:

| Field | Meaning |
|---|---|
| `id` | Stable local identifier, unique within the manifest. |
| `label` / `why` | Human-readable action and consequence explanation. |
| `match` | Transport selector, e.g. `{ "protocol": "mcp", "tool": "release_payment" }` or `{ "protocol": "http", "method": "POST", "path": "/release-payment" }`. |
| `action_type` | Canonical EP action bound into the receipt. |
| `risk` | `low`, `medium`, `high`, or `critical`. |
| `receipt_required` | Boolean gate. |
| `assurance_class` | `software`, `class_a`, or `quorum`. |
| `max_age_sec` | Maximum accepted receipt age. |
| `quorum` | Optional quorum requirement for high-stakes actions. |
| `control.authorization` | Optional closed `{ authorization_endpoint, flow }` acquisition descriptor. |
| `control.execution_binding.required_fields` | Material action fields that both approval and execution bind. |
| `control.execution_binding.caid_selector` | Optional `{ "field": "action_caid" }` selector for the CAID that identifies the exact action content. |

## EP-APPROVAL-v1 acquisition

The authorization descriptor is discovery, not authority. A client MUST match
the exact endpoint and flow against configuration obtained out of band before
making a network request. A challenge-selected endpoint cannot bootstrap its
own trust. Receipt verification remains offline under relying-party-pinned
issuer and approver keys.

The current EMILIA reference acquisition server is intentionally narrower than
the Receipt Required enforcement manifest: it registers only the
`payment.release` Class-A profile. Accordingly, the public Action Control
manifest advertises `control.authorization` only on its MCP and HTTP
`payment.release` descriptors. Other receipt-required actions remain
challenge-only until an exact server-owned profile, identity mapping, and (when
applicable) quorum ceremony exist. A server MUST NOT advertise acquisition for
an action its POST contract cannot complete.

1. The agent POSTs `{ flow, challenge, action, approver_id, idempotency_key }`
   using a requester credential injected from its own secret store. The action
   is closed JSON and contains every challenged material field. The challenge
   and manifest can select an endpoint but can never supply that credential.
2. The authorization service recomputes the action digest and CAID under its
   registered server-side profile. It derives tenant, environment, requester,
   policy, and presentation from authenticated/server-owned state.
3. The service returns `201` with an opaque `request_id`, same-origin
   `approval_url`, separate private `poll_token`, `status: "pending"`, and a
   fixed expiry. The request id, human-review capability, and polling capability
   are distinct.
4. The named human reviews the server-canonical action and performs the pinned
   assurance ceremony. A pending, denied, expired, cancelled, unsigned, or
   operator-only object is not an approval receipt.
5. The agent polls `GET {authorization_endpoint}/{request_id}` with
   `Authorization: EP-Approval {poll_token}`. Only `status: "approved"` may carry
   `receipt`; all other states omit it.
6. The agent retries the original service. The service verifies the terminal
   receipt against its own pins, recomputes exact action/CAID bindings, reserves
   one-time consumption, then crosses the effect boundary.

The reference implementation follows no acquisition redirects, bounds response
bytes, uses strict JSON, requires an out-of-band injected requester credential,
and requires durable idempotency. The approval URL works on a phone, but this
release does not claim a native-app bridge; native inbox routing requires a
separate authoritative tenant-to-enrollment mapping. Edge/gateway examples are
experimental deployment references, not independent audits.

## MCP profile

For MCP servers, `match.protocol` is `mcp` and `match.tool` is the tool name. A
server that receives a call for a `receipt_required: true` tool without proof
returns the same problem object as a tool result or structured error, using
`status: 428` and the `Receipt-Required` challenge fields.

Implementation guide: [`docs/guides/RECEIPT-REQUIRED-MCP.md`](guides/RECEIPT-REQUIRED-MCP.md).

## A2A profile

For A2A tasks, the producer can expose the same manifest and put the challenge in
task metadata when an irreversible task is blocked:

```json
{
  "state": "input-required",
  "reason": "emilia_receipt_required",
  "receipt_required": {
    "action": "deploy.production",
    "manifest": "/.well-known/agent-action-control.json",
    "proof_header": "X-EMILIA-Receipt"
  }
}
```

## Verification

The challenge says what proof is required and, optionally, how to acquire it.
Acceptance still depends on the relying party's authorization receipt verifier:

1. The receipt signature verifies against a trusted issuer key.
2. The signed canonical action, action digest, required fields, and CAID match
   the executor-observed action.
3. The receipt is fresh enough for the manifest's `max_age_sec`.
4. Required assurance class and quorum predicates hold.
5. Production enforcement consumes the receipt before mutation and rejects replay.

Neither the manifest, a CAID, nor the acquisition endpoint is a permission
grant. They describe refusal and evidence acquisition. Authority still comes
from pinned issuer/human keys, policy, exact signed content, and one-time
consequence enforcement.
