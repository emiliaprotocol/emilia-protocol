# Connected approval endpoint prototype

Status: **experimental pre-standard connected prototype**.

This surface is not a production API, is not a certification program, and is
not an interoperability claim. It connects existing EMILIA receipt, Class-A
signoff, one-time consumption, and evidence code into one deliberately bounded
workflow for evaluation.

## Contract boundary

The prototype exposes exactly these routes:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/cloud/approvals` | List the authenticated tenant's connected approval queue |
| `POST` | `/api/cloud/approvals` | Create one fixed `large_payment_release` approval request |
| `POST` | `/api/cloud/approvals/{receiptId}/consume` | Consume an approved receipt exactly once |
| `GET` | `/api/cloud/approvals/{receiptId}/evidence` | Export the receipt's JSON evidence packet |

All four operations require:

```http
Authorization: Bearer <tenant Cloud API key>
```

The key must be active, tenant-bound, and carry either the named
`approval_request` capability or `admin`. `read` and `write` alone do not grant
this capability. Queue, consume, and evidence reads remain scoped to receipts
created for the authenticated tenant through this connected flow.

## Fixed action and CAID

The caller does not select an action type. `POST /api/cloud/approvals` always
creates the Guard action `large_payment_release` in enforce mode.

The server also computes `action_caid` using the registered CAID action type
`payment.release.1` and the `jcs-sha256` suite. Its shape is:

```text
caid:1:payment.release.1:jcs-sha256:<43-character unpadded base64url digest>
```

For the CAID typed content, the server maps:

| Prototype input | `payment.release.1` material field |
| --- | --- |
| Canonical decimal representation of `amount` | `amount` |
| `currency` | `currency` |
| `payment_destination_hash` | `beneficiary_account` |
| `payment_reference` | `payment_instruction_id` |
| Trimmed `counterparty_name` | optional `memo` |

CAID identifies exact canonical typed action content. It does not establish
identity, authority, approval, authorization, execution, safety, or business
wisdom. The Guard `action_hash`, Class-A signoff, policy evaluation, and
one-time consume checks remain separate controls.

## Create an approval

`POST /api/cloud/approvals` requires:

```json
{
  "amount": 82000,
  "currency": "USD",
  "counterparty_name": "Acme Medical Supply",
  "payment_destination_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "payment_reference": "payment:invoice-1842",
  "approver_id": "approver:cfo@example.com"
}
```

An optional `comment` is truncated to 500 characters. Input constraints are:

- `amount`: positive finite JSON number, no greater than
  `1,000,000,000,000`.
- `currency`: exactly three uppercase letters.
- `counterparty_name`: 1–160 printable characters.
- `payment_destination_hash`: `sha256:` followed by exactly 64 lowercase
  hexadecimal characters.
- `payment_reference`: 3–200 safe identifier characters, starting with an
  alphanumeric character; `..` is forbidden.
- `approver_id`: 3–128 characters from `[A-Za-z0-9:_.@-]`.

The route creates a one-hour receipt and signoff window. It fails rather than
continue if the receipt does not require Class-A assurance.

A successful `201` response has this shape:

```json
{
  "receipt_id": "tr_<32-lowercase-hex>",
  "action_hash": "<64-lowercase-hex>",
  "action_caid": "caid:1:payment.release.1:jcs-sha256:<43-character-base64url>",
  "expires_at": "2026-07-20T00:00:00.000Z",
  "signoff_id": "sig_<32-lowercase-hex>",
  "approver_id": "approver:cfo@example.com",
  "required_assurance": "A",
  "status": "pending",
  "review_path": "/signoff/sig_<32-lowercase-hex>",
  "implementation_status": "prototype"
}
```

## Class-A review

The returned `review_path` opens the existing WebAuthn/WYSIWYS review
experience. The named approver uses an enrolled device credential to decide the
exact action context. The connected create route checks that
`required_assurance` is `A` before returning the request.

The plain bearer-key routes
`POST /api/v1/signoffs/{signoffId}/approve` and
`POST /api/v1/signoffs/{signoffId}/reject` are not substitutes. They accept
`approved_action_hash` and create service-recorded Class-C decisions. They
refuse receipts requiring Class-A WebAuthn evidence.

## Queue states

`GET /api/cloud/approvals` returns at most the tenant-scoped connected queue,
plus counts for:

- `pending`
- `approved`
- `rejected`
- `expired`
- `consumed`

Each queue item exposes `action_caid`, the fixed
`action_type: "large_payment_release"`, the action hash, payment summary
fields including `payment_destination_hash`, approver and signoff identifiers,
review path, and consumption time when present. `action_caid` remains a
typed-content identifier, not an authorization result.

## One-time consume

After a Class-A approval, call:

```http
POST /api/cloud/approvals/{receiptId}/consume
Content-Type: application/json
Authorization: Bearer <tenant Cloud API key>

{"action_hash":"<the exact 64-lowercase-hex action_hash returned at creation>"}
```

The route delegates to the receipt consume gate with a fixed
`executing_system` value of `emilia_cloud_approval_endpoint`. The action hash
must match issuance, the receipt must be unexpired and approved, and an already
consumed receipt returns a conflict instead of becoming reusable.

Consume records one-time use of the authorization. This prototype route does
not itself move money or prove that an external payment executed.

## Evidence export

`GET /api/cloud/approvals/{receiptId}/evidence` returns the canonical JSON
evidence projection for the tenant-owned receipt. It includes the audit
timeline, Guard action hash, policy result, recorded signoff state, consume
state, and signed EP receipt fields when the underlying evidence route can
honestly produce them. In a signed packet, the server-computed CAID is bound at
`document.payload.claim.canonical_action.action_caid`. The create response and
queue expose `action_caid` directly.

A pending, rejected, expired, or incomplete receipt may have `signed: false`
and null signed-document fields. Evidence export does not turn a prototype into
production, certify a deployment, or establish interoperability.

## Explicit non-claims

- The prototype does not provide a generic receipt-minting API.
- It does not let the caller choose an action type or executing system.
- It does not execute a payment.
- A CAID does not establish authorization.
- A recorded approval does not prove that an action is legal, safe, wise, or
  successfully executed.
- Offline receipt verification and one-time online consumption are distinct
  properties.
