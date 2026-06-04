# EP-RECEIPT-v1 — Trust Receipt Format

A **Trust Receipt** is a signed, offline-verifiable record that a specific action was
authorized — by whom, under what policy, with what outcome. Anyone with the signer's
public key can verify one with no EP account, no API, no network. This document specifies
the format precisely enough to implement a verifier in any language.

> Status: implementable reference spec (two interoperating implementations exist —
> `@emilia-protocol/verify` (JS) and `emilia-verify` (Python)). Intended as the basis for a
> future IETF informational draft. Adoption first; standardization follows what people verify.

## 1. Document
```json
{
  "@version": "EP-RECEIPT-v1",
  "payload": { "...": "the signed claim (see §2)" },
  "signature": { "algorithm": "ed25519", "value": "<base64url>" },
  "anchor": {
    "leaf_hash": "<hex sha-256>",
    "merkle_proof": [ { "hash": "<hex>", "position": "left|right" } ],
    "merkle_root": "<hex>"
  }
}
```
`anchor` is OPTIONAL. `@version`, `payload`, and `signature` are REQUIRED.

## 2. Payload (conventional shape)
The payload is application-defined; the signature covers it whole. EP's convention:
```json
{
  "receipt_id": "ep_...",
  "issued_at": "2026-06-04T00:00:00Z",
  "claim": {
    "action": "payment.release",
    "outcome": "allow | allow_with_signoff | deny",
    "approver": "operator:<named human>",
    "context": { "amount": 50000, "destination": "acct_9f12", "currency": "USD" }
  }
}
```

## 3. Canonicalization (the exact bytes that get signed)
Recursive, depth-first key sort at every level:
- **object** → `{` + keys sorted lexicographically, each rendered as `json(key) ":" canon(value)`, joined by `,` + `}`
- **array** → `[` + `canon(element)` for each, joined by `,` + `]`
- **scalar** → JSON encoding (UTF-8, non-ASCII NOT escaped; matches `JSON.stringify`)

This is byte-identical on signer and verifier for any nesting depth. (A shallow sort is **not**
sufficient — nested keys must be ordered too.)

## 4. Signature
- Algorithm: **Ed25519**.
- Signed material: `canonicalize(payload)` as UTF-8 bytes.
- Public key: **base64url** of the **SPKI DER** encoding.
- `signature.value`: **base64url** of the 64-byte signature.

## 5. Merkle anchor (optional)
- `leaf_hash`: hex SHA-256.
- Each proof step folds the running hash with a sibling: `sorted([a, b])` then `SHA-256(lo || hi)` (hex).
  `position: "left"` means the sibling is on the left.
- The reconstructed value MUST equal `merkle_root`. Proof length is bounded (≤ 20).

## 6. Verification algorithm
1. `@version` ∈ {`EP-RECEIPT-v1`}, else invalid.
2. Ed25519-verify `signature.value` over `canonicalize(payload)` with the signer's public key.
3. If `anchor` is present, reconstruct the root from `leaf_hash` + `merkle_proof`; it MUST equal `merkle_root`.
4. **Valid** iff version holds, signature verifies, and (anchor absent OR anchor reconstructs).

A malformed receipt MUST verify as invalid — never raise.

## 7. Reference implementations
| Language | Package | Crypto |
|---|---|---|
| JavaScript / Node | `@emilia-protocol/verify` | Node built-in `crypto` |
| Python | `emilia-verify` | `cryptography` |

Interop is tested: a receipt signed by the JS side verifies under the Python implementation
(`packages/python-verify/tests/test_verify.py`) and vice versa.

Apache-2.0.
