# EP Federation Registry

**Status:** Convention (PIP-006 acceptance gate #2)
**Applies to:** EP-RECEIPT-v1, EP-CORE-v1.0
**Last updated:** 2026-06-11

This document defines how EP operators are *discovered* so that a receipt issued
by one operator can be verified by any other. It is a **published convention**,
not a service owned by EMILIA — exactly as RFC 7517 (JWKS) is a convention, not
an endpoint Google runs. Any operator can implement it; no operator is
privileged.

> Federation enables **receipt portability**. It does not enable trust
> laundering. Discovery tells you *which key* an operator advertises; it never
> tells you to *trust* that operator. Trust remains each relying party's local
> policy. — PIP-006

---

## 1. What an operator publishes

Every conformant EP operator MUST serve three surfaces over HTTPS. These are the
entire federation contract; nothing else is required to verify a foreign
receipt.

| Surface | Path | Purpose |
|---|---|---|
| Operator self-claim | `GET /.well-known/ep-trust.json` | capabilities, protocol versions, supported extensions |
| Key discovery | `GET /.well-known/ep-keys.json` | current + historical Ed25519 verification keys |
| Verifier-of-record | `GET /api/verify/{receipt_id}` | well-formedness + signed-by-advertised-key + revocation status |

### 1.1 `ep-keys.json` shape

```jsonc
{
  "version": "1.1",
  "operator_id": "ep_operator_emilia_primary",
  "protocol_version": "EP-CORE-v1.0",
  "cache_ttl_seconds": 300,
  "verify_url_template": "https://www.emiliaprotocol.ai/api/verify/{receipt_id}",
  "keys": {
    "<entity_id>": { "public_key": "<base64url SPKI DER>", "algorithm": "Ed25519" }
  },
  "historical_keys": {
    "<entity_id>": [
      { "public_key": "<base64url SPKI DER>", "algorithm": "Ed25519", "retired_at": "<ISO-8601>" }
    ]
  }
}
```

- **`keys`** — currently-valid signing keys, by `entity_id`.
- **`historical_keys`** — retired keys that still verify pre-rotation receipts
  (rotation safety). Empty until the operator's first signing-key rotation.
- **`cache_ttl_seconds`** — how long a relying party MAY cache this document. A
  rotation propagates within this window.
- **`verify_url_template`** — where to confirm revocation for a given receipt.

The reference server implementation is `app/api/discovery/keys/route.js`, backed
by `entity_signing_key_history` (migration 094) for the historical set.

---

## 2. How a receipt points back to its operator

Every EP-RECEIPT-v1 MUST carry, in its `signature` block:

```jsonc
"signature": {
  "signer": "ep_operator_a",                                  // issuing operator entity_id
  "key_discovery": "https://op-a.example/.well-known/ep-keys.json",
  "algorithm": "Ed25519",
  "value": "<base64url signature over canonical payload>"
}
```

`signer` + `key_discovery` are what make a receipt **self-locating**: a relying
party who has never heard of Operator A can still find A's keys from the receipt
alone.

---

## 3. How a relying party verifies (Operator B)

This is implemented and tested as
`@emilia-protocol/verify` → `verifyFederatedReceipt` (online) /
`verifyFederatedReceiptOffline` (air-gapped). **Requires version 1.3.0** —
available from source in `packages/verify/`; the npm publish of 1.3.0 is
pending, and earlier npm releases do not carry the federation exports. The
algorithm:

1. Read `signature.signer` and `signature.key_discovery` from the receipt.
2. Fetch (or use a cached, un-expired copy of) the operator's `ep-keys.json`.
3. Resolve candidate keys for `signer`: **current first, then historical**.
4. Verify the Ed25519 signature over the canonical payload against each
   candidate; the first that validates wins. A tampered payload or an
   unadvertised key matches none.
5. Consult the operator's `verify_url_template` for revocation. A receipt the
   operator has revoked is **verified but not accepted**.
6. Apply **local** trust policy. `accepted = verified && !revoked` is the
   default verdict; a relying party is free to be stricter.

```js
// requires @emilia-protocol/verify >= 1.3.0 (from packages/verify/ until the npm publish lands)
import { verifyFederatedReceipt } from '@emilia-protocol/verify';

const verdict = await verifyFederatedReceipt(receipt);
// { accepted, verified, revoked, signer, keyMatched: 'current'|'historical', checks }
```

The safety properties of this path are formally modeled in
`formal/ep_federation.als` (7 assertions, no counterexample under the Alloy
model checker; run in CI on every change to `formal/*.als`).

---

## 4. Registering an operator

There is no central registrar. An operator joins the federation by:

1. Standing up the three surfaces in §1 at a stable HTTPS origin.
2. Passing the cross-operator conformance harness against the primary:
   `node conformance/federation.mjs https://<your-operator-origin>`.
3. (Optional, recommended) opening a PR to the operator list below so relying
   parties can pin a known origin. Pinning is a *convenience*, never a
   *requirement* — a receipt's `key_discovery` URL is always authoritative.

### Known operators

| Operator ID | Origin | Status |
|---|---|---|
| `ep_operator_emilia_primary` | `https://www.emiliaprotocol.ai` | primary |
| _your operator here_ | — | open a PR |

> **Acceptance status (PIP-006):** the cross-operator verification path is
> implemented and verified against a **self-hosted** second operator (the
> conformance harness). Full acceptance additionally requires an **independent
> third-party** operator to stand up the three surfaces and pass the harness
> end-to-end. That is an invitation, not a blocker: the contract above is
> everything such an operator needs.

---

## 5. Security notes

- **Key rotation** — rotate by moving the old key from `keys` to
  `historical_keys` and publishing the new key in `keys`. Never delete a
  historical key while receipts signed under it may still be presented.
- **Revocation** — operators honor *their own* revocation lists only. A
  revocation that arrives after an action executed is a *dispute*, not a
  verification failure.
- **Time skew** — receipt-expiry checks tolerate NTP-bounded skew; an operator
  that drifts >30s from UTC SHOULD stop issuing receipts.
- **No transitive trust** — accepting Operator A's receipt does not import A's
  policy decisions, trust scores, or audit log. Evidence travels; authority does
  not.
