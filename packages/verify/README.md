# @emilia-protocol/verify

**Zero-dependency offline verification for EP trust receipts.**

Verify Ed25519-signed trust receipts, Merkle anchor proofs, and commitment proofs using only Node.js built-in `crypto`. No EP infrastructure required. No API key. No account. Just math.

This is the core primitive that makes EP a **protocol**, not an API.

## Install

```bash
npm install @emilia-protocol/verify
```

## Quick Start

```js
import { verifyReceipt } from '@emilia-protocol/verify';

// Load a receipt document (EP-RECEIPT-v1 format)
const receipt = JSON.parse(fs.readFileSync('receipt.json', 'utf8'));

// Get the signer's public key (from /.well-known/ep-keys.json)
const publicKey = 'MFYwEAYHKoZIzj0CAQYFK4EEAA...'; // base64url SPKI DER

const result = verifyReceipt(receipt, publicKey);
console.log(result);
// { valid: true, checks: { version: true, signature: true, anchor: null } }
```

## API

### `verifyReceipt(doc, publicKeyBase64url)`

Verify an EP-RECEIPT-v1 document. Performs three independent checks:

1. **Version** — Document format is EP-RECEIPT-v1
2. **Signature** — Ed25519 signature over canonical payload
3. **Anchor** (if present) — Merkle proof reconstructs claimed root

Returns `{ valid, checks, error? }`.

### `verifyMerkleAnchor(leafHash, proof, expectedRoot)`

Verify a Merkle inclusion proof. The root can be independently checked on Base L2 via [Basescan](https://basescan.org).

Returns `boolean`.

### `verifyCommitmentProof(proof, publicKeyBase64url)`

Verify an EP-PROOF-v1 commitment proof. Checks expiry and signature.

Returns `{ valid, claim, error? }`.

### `verifyReceiptBundle(bundle, publicKeyBase64url)`

Verify all receipts in an EP-BUNDLE-v1 document.

Returns `{ valid, total, verified, failed }`.

## Design Principles

- **Zero dependencies** — Only `node:crypto`. No supply chain risk.
- **Offline-first** — No network calls. No EP server needed.
- **Deterministic** — Canonical JSON serialization for reproducible signatures.
- **Auditable** — Single file, ~170 lines. Read the entire thing in 5 minutes.

## How It Works

```
Receipt Document (EP-RECEIPT-v1)
├── payload (canonical JSON)
├── signature
│   ├── algorithm: "Ed25519"
│   ├── signer: "ep_entity_..."
│   └── value: base64url signature
└── anchor (optional)
    ├── leaf_hash: SHA-256 of receipt
    ├── merkle_proof: [{hash, position}, ...]
    ├── merkle_root: root hash
    └── chain: "base-sepolia"

Verification:
1. Canonicalize payload → sorted-key JSON
2. Verify Ed25519(canonical_payload, signature, public_key)
3. If anchor: reconstruct Merkle root from proof, compare
```

## Getting Public Keys

Signer public keys are discoverable at `/.well-known/ep-keys.json` on any EP operator:

```bash
curl https://ep.example.com/.well-known/ep-keys.json
```

## License

Apache-2.0
