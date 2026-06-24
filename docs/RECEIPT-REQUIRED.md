<!-- SPDX-License-Identifier: Apache-2.0 -->
# Receipt Required v0.1

Receipt Required is the additive challenge-response rail for irreversible agent
actions:

```text
agent attempts irreversible action
service returns Receipt Required
agent obtains an EP-RECEIPT-v1 authorization receipt
agent retries with the receipt
service verifies offline, consumes if applicable, then executes
```

It does not rename EP Core and it does not replace authorization receipts. It is
the small protocol moment that lets services say:

> No receipt, no irreversible action.

**Conformance & badge:** the ritual is testable — see
[RECEIPT-REQUIRED-CONFORMANCE.md](RECEIPT-REQUIRED-CONFORMANCE.md) for the RR-1
level and the `receiptRequiredConformance()` harness that earns the badge.

## HTTP profile

New integrations SHOULD use HTTP `428 Precondition Required` when the missing
precondition is an authorization receipt.

```http
HTTP/1.1 428 Precondition Required
Content-Type: application/problem+json
Receipt-Required: action="payment.release", proof="X-EMILIA-Receipt", manifest="/.well-known/agent-actions.json", profile="EP-RECEIPT-v1", assurance="class_a", max_age="900"
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
    "manifest": "/.well-known/agent-actions.json",
    "challenge_header": "Receipt-Required",
    "proof_header": "X-EMILIA-Receipt",
    "header": "X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)",
    "assurance_class": "class_a",
    "max_age_sec": 900
  }
}
```

Existing EMILIA demand-loop demos and x402-compatible flows MAY continue to use
HTTP `402` for compatibility. The semantics are the same: the action is refused
until the caller presents a valid authorization receipt.

## Action Risk Manifest

A service publishes its risk contract at:

```text
/.well-known/agent-actions.json
```

The manifest is intentionally boring JSON. It tells agents, MCP clients, auditors,
and test harnesses which actions are read-only and which actions require an
authorization receipt.

Required top-level fields:

| Field | Meaning |
|---|---|
| `@version` | Must be `EP-ACTION-RISK-MANIFEST-v0.1`. |
| `service` | Human-readable service metadata and canonical manifest URL. |
| `receipt_required` | Transport defaults: status, challenge header, proof header, receipt profile. |
| `defaults` | Default behavior for read-only, missing, invalid, or stale receipts. |
| `actions` | List of action requirements. |

Each action entry has:

| Field | Meaning |
|---|---|
| `id` | Stable local identifier, unique within the manifest. |
| `description` | Human-readable reason this action exists. |
| `match` | Transport selector, e.g. `{ "protocol": "mcp", "tool": "release_payment" }` or `{ "protocol": "http", "method": "POST", "path": "/release-payment" }`. |
| `action_type` | Canonical EP action bound into the receipt. |
| `risk` | `low`, `medium`, `high`, or `critical`. |
| `receipt_required` | Boolean gate. |
| `assurance_class` | `software`, `class_a`, or `quorum`. |
| `max_age_sec` | Maximum accepted receipt age. |
| `quorum` | Optional quorum requirement for high-stakes actions. |

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
    "manifest": "/.well-known/agent-actions.json",
    "proof_header": "X-EMILIA-Receipt"
  }
}
```

## Verification

The challenge only says what proof is required. Acceptance still depends on the
authorization receipt verifier:

1. The receipt signature verifies against a trusted issuer key.
2. The receipt action matches the requested action.
3. The receipt is fresh enough for the manifest's `max_age_sec`.
4. Required assurance class and quorum predicates hold.
5. Production enforcement consumes the receipt before mutation and rejects replay.

The manifest is not a permission grant. It is a machine-readable refusal policy:
which action requires proof, and what proof the caller must bring.
