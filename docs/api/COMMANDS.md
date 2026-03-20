# EMILIA Protocol -- Command Reference

All 17 command types flow through `protocolWrite()` in `lib/protocol-write.js`. Each command produces a `protocol_events` entry and delegates to a canonical handler.

## Command Structure

Every command has this shape:

```js
{
  type: string,       // One of COMMAND_TYPES (see below)
  input: object,      // Type-specific input data
  actor: string|object, // Entity ID or entity object from auth middleware
  requestMeta: {      // Optional
    role: string,     // Operator role (default: 'entity')
    source: string,   // Request source (default: 'api')
  }
}
```

## Receipt Commands

### `submit_receipt`

Submit a trust-bearing receipt for an interaction.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.entity_id` | string | Yes | The entity this receipt is about |
| `actor` | string | Yes | The submitting entity |

**Aggregate type**: `receipt`
**Handler**: `canonicalSubmitReceipt(input, actor)`
**Success response**: `{ receipt: { receipt_id, entity_id, ... } }`
**Error codes**: `VALIDATION_ERROR` (400), `ABUSE_DETECTED` (429)

---

### `submit_auto_receipt`

Submit an automated receipt via machine-to-machine integration. Same semantics as `submit_receipt` but authenticated via `EP_AUTO_SUBMIT_SECRET` instead of entity API key.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.entity_id` | string | Yes | The entity this receipt is about |
| `actor` | string | Yes | The submitting system identity |

**Aggregate type**: `receipt`
**Handler**: `canonicalSubmitAutoReceipt(input, actor)`
**Success response**: `{ receipt: { receipt_id, entity_id, ... } }`
**Error codes**: `VALIDATION_ERROR` (400)

---

### `confirm_receipt`

Bilateral confirmation of a receipt by the counterparty.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.receipt_id` | string | Yes | Receipt to confirm |
| `input.confirming_entity_id` | string | Yes | Entity confirming the receipt |
| `input.confirm` | boolean | Yes | `true` to confirm, `false` to reject |

**Aggregate type**: `receipt`
**Handler**: `canonicalBilateralConfirm(receipt_id, confirming_entity_id, confirm)`
**Success response**: Confirmation result object
**Error codes**: `VALIDATION_ERROR` (400)

## Commit Commands

### `issue_commit`

Issue a verifiable, revocable trust commitment from one entity.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.entity_id` | string | Yes | Issuing entity |
| `input.action_type` | string | Yes | Type of action being committed to |

**Aggregate type**: `commit`
**Handler**: `issueCommit(input)`
**Success response**: `{ commit_id, ... }`
**Error codes**: `VALIDATION_ERROR` (400)

---

### `verify_commit`

Verify an issued commit's cryptographic signature and status.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.commit_id` | string | Yes | Commit to verify |

**Aggregate type**: `commit`
**Handler**: `verifyCommit(commit_id)`
**Success response**: Verification result with signature validity
**Error codes**: `VALIDATION_ERROR` (400)

---

### `revoke_commit`

Revoke a previously issued commit.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.commit_id` | string | Yes | Commit to revoke |
| `input.reason` | string | Yes | Reason for revocation |

**Aggregate type**: `commit`
**Handler**: `revokeCommit(commit_id, reason)`
**Success response**: Revocation result
**Error codes**: `VALIDATION_ERROR` (400)

## Dispute Commands

### `file_dispute`

File a formal dispute against a receipt.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.receipt_id` | string | Yes | Receipt being disputed |
| `input.reason` | string | Yes | Reason for the dispute |
| `actor` | string | Yes | Filing entity |

**Aggregate type**: `dispute`
**Handler**: `canonicalFileDispute(input, actor)`
**Success response**: `{ dispute_id, ... }`
**Error codes**: `VALIDATION_ERROR` (400), `ABUSE_DETECTED` (429)
**Abuse checks**: Retaliatory filing detection, dispute flooding detection

---

### `respond_dispute`

Submit a response to an open dispute.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.dispute_id` | string | Yes | Dispute to respond to |
| `input.responder_id` | string | Yes | Responding entity |
| `input.response` | string | Yes | Response text |
| `input.evidence` | object | No | Supporting evidence |

**Aggregate type**: `dispute`
**Handler**: `canonicalRespondDispute(dispute_id, responder_id, response, evidence)`
**Success response**: Response result
**Error codes**: `VALIDATION_ERROR` (400)

---

### `resolve_dispute`

Resolve a dispute (operator action).

| Field | Type | Required | Description |
|---|---|---|---|
| `input.dispute_id` | string | Yes | Dispute to resolve |
| `input.resolution` | string | Yes | Resolution outcome (`upheld`, `reversed`, `dismissed`) |
| `input.rationale` | string | Yes | Operator's reasoning |
| `input.operator_id` | string | Yes | Resolving operator |

**Aggregate type**: `dispute`
**Handler**: `canonicalResolveDispute(dispute_id, resolution, rationale, operator_id)`
**Success response**: Resolution result
**Error codes**: `VALIDATION_ERROR` (400)
**State machine**: Transitions dispute from `under_review` to `upheld`, `reversed`, or `dismissed`

---

### `appeal_dispute`

Appeal a dispute resolution.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.dispute_id` | string | Yes | Dispute to appeal |
| `input.reason` | string | Yes | Appeal reason (minimum 10 characters) |
| `input.appealer_id` | string | No | Appealing entity (defaults to `actor`) |
| `input.evidence` | object | No | Supporting evidence |

**Aggregate type**: `dispute`
**Handler**: `canonicalAppealDispute(dispute_id, { id: appealer_id }, reason, evidence)`
**Success response**: Appeal result
**Error codes**: `VALIDATION_ERROR` (400)
**State machine**: Transitions dispute from `upheld`, `reversed`, or `dismissed` to `appealed`

---

### `resolve_appeal`

Resolve an appeal (senior operator action).

| Field | Type | Required | Description |
|---|---|---|---|
| `input.dispute_id` | string | Yes | Dispute whose appeal is being resolved |
| `input.resolution` | string | Yes | Appeal resolution (`appeal_upheld`, `appeal_reversed`, `appeal_dismissed`) |
| `input.rationale` | string | Yes | Operator's reasoning |
| `input.operator_id` | string | Yes | Resolving operator |

**Aggregate type**: `dispute`
**Handler**: `canonicalResolveAppeal(dispute_id, resolution, rationale, operator_id)`
**Success response**: Appeal resolution result
**Error codes**: `VALIDATION_ERROR` (400)
**State machine**: Transitions dispute from `appealed` to terminal state (`appeal_upheld`, `appeal_reversed`, `appeal_dismissed`)

---

### `withdraw_dispute`

Withdraw a dispute (filing party action).

| Field | Type | Required | Description |
|---|---|---|---|
| `input.dispute_id` | string | Yes | Dispute to withdraw |
| `input.withdrawer_id` | string | No | Withdrawing entity (defaults to `actor`) |

**Aggregate type**: `dispute`
**Handler**: `canonicalWithdrawDispute(dispute_id, { id: withdrawer_id })`
**Success response**: Withdrawal result
**Error codes**: `VALIDATION_ERROR` (400)
**State machine**: Transitions dispute from `open` to `withdrawn` (terminal)

## Report Commands

### `file_report`

File a trust report against an entity (abuse, fraud, etc.).

| Field | Type | Required | Description |
|---|---|---|---|
| `input.entity_id` | string | Yes | Entity being reported |
| `input.report_type` | string | Yes | Type of report |
| `input.description` | string | Yes | Description of the issue |

**Aggregate type**: `report`
**Handler**: `canonicalFileReport(input)`
**Success response**: `{ report_id, ... }`
**Error codes**: `VALIDATION_ERROR` (400), `ABUSE_DETECTED` (429)
**Abuse checks**: Repeated identical reports, brigading, IP flooding

## Handshake Commands

### `initiate_handshake`

Initiate a pre-action trust handshake.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.mode` | string | Yes | Handshake mode |
| `input.policy_id` | string | Yes | Policy governing this handshake |
| `input.parties` | array | Yes | Non-empty array of party definitions (with roles: initiator, responder, verifier, delegate) |

**Aggregate type**: `handshake`
**Handler**: `_handleInitiateHandshake(command)` (lazy-loaded from `lib/handshake/create.js`)
**Success response**: Handshake record with binding details
**Error codes**: `VALIDATION_ERROR` (400)

---

### `add_presentation`

Add a presentation (identity claims) to an active handshake.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.handshake_id` | string | Yes | Target handshake |
| `input.party_role` | string | Yes | Role of the presenting party |
| `input.presentation_hash` | string | Yes | Hash of the presentation content |

**Aggregate type**: `handshake`
**Handler**: `_handleAddPresentation(command)` (lazy-loaded from `lib/handshake/present.js`)
**Success response**: Presentation result
**Error codes**: `VALIDATION_ERROR` (400)

---

### `verify_handshake`

Verify a handshake and consume its binding (one-time use).

| Field | Type | Required | Description |
|---|---|---|---|
| `input.handshake_id` | string | Yes | Handshake to verify |

**Aggregate type**: `handshake`
**Handler**: `_handleVerifyHandshake(command)` (lazy-loaded from `lib/handshake/verify.js`)
**Success response**: Verification result with consumed binding
**Error codes**: `VALIDATION_ERROR` (400)
**Replay prevention**: Sets `consumed_at` on the binding. The `consumed_at IS NULL` filter prevents double consumption.
**Policy enforcement**: Re-loads and re-hashes the policy at verification time. Rejects if hash differs from initiation (`policy_hash_mismatch`).

---

### `revoke_handshake`

Revoke an active handshake.

| Field | Type | Required | Description |
|---|---|---|---|
| `input.handshake_id` | string | Yes | Handshake to revoke |
| `input.reason` | string | Yes | Reason for revocation |

**Aggregate type**: `handshake`
**Handler**: `_handleRevokeHandshake(command)` (lazy-loaded from `lib/handshake/finalize.js`)
**Success response**: Revocation result
**Error codes**: `VALIDATION_ERROR` (400)

## Pipeline Stages (All Commands)

Every command passes through these stages in `protocolWrite()`:

1. `assertInvariants(command)` -- verify command has a known type and valid structure
2. `VALIDATORS[command.type](command)` -- type-specific input validation
3. `resolveAuthority(command)` -- normalize actor identity to `{ id, role, source }`
4. `checkAbuse()` -- abuse detection (for `file_dispute` and `file_report` only)
5. `computeIdempotencyKey()` -- SHA-256 of `type:actor:JSON(input)`, checked against 10-minute TTL cache
6. `HANDLERS[command.type](command)` -- delegate to canonical function
7. `buildProtocolEvent()` -- construct append-only event record
8. `appendProtocolEvent()` -- persist to `protocol_events` (MUST succeed or entire operation is rejected)
9. `setIdempotencyCache()` -- cache result for dedup
10. `emitTelemetry()` -- structured observability log (fire-and-forget)
11. Return result projection

## Idempotency

Idempotency key: `SHA-256(command.type + ":" + actor + ":" + JSON.stringify(input))`

If the same command is submitted within 10 minutes, the cached result is returned with `_idempotent: true` appended. No duplicate event is created.
