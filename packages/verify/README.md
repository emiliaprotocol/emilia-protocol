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

## In the browser, edge, or Deno

The default entry uses Node's `crypto`. For any runtime with the W3C Web Crypto
API — every modern browser, Deno, Cloudflare Workers, Vercel Edge — import the
`/web` build instead. Same inputs, same `{ valid, checks }` output (proven
byte-for-byte in `web.test.js`); the functions are `async` because Web Crypto is.

```js
import { verifyReceipt, verifyWebAuthnSignoff } from '@emilia-protocol/verify/web';

const r = await verifyReceipt(receipt, publicKey);          // Ed25519
const s = await verifyWebAuthnSignoff(signoff, approverKey, // ECDSA P-256
  { rpId: 'emiliaprotocol.ai' });
```

This is what powers [emiliaprotocol.ai/verify](https://www.emiliaprotocol.ai/verify):
a relying party verifies a receipt entirely in their own tab — nothing uploaded,
no server trusted. Receipts use Ed25519; Class-A device signoffs use ECDSA P-256
over a WebAuthn assertion (the `/web` build converts the DER signature to the raw
form Web Crypto expects). Call `isSupported()` to feature-detect.

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

### `verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, { rpId? })`

Verify a Class-A (device-bound key) signoff fully offline: the WebAuthn
challenge equals SHA-256(JCS(context)) for the exact signed context, the
authenticator asserted user presence + verification, and the ECDSA P-256
signature verifies against the enrolled approver key.

Returns `{ valid, checks, error? }`.

### `verifyTrustReceipt(receipt, { approverKeys, logPublicKey })` — *requires 1.3.0*

The full offline verification algorithm from the Internet-Draft
(draft-schrock-ep-authorization-receipts, Section 6.3) over a Section 6.2
Trust Receipt — all six steps, no network:

1. Recompute the action hash from the canonical Action Object
2. Recompute each context hash; confirm it commits to the action hash, the policy hash, and a distinct approver
3. Verify each signoff signature (Class-A WebAuthn or Class-B Ed25519) against the pinned approver key, checking the key's validity window
4. Separation of duties — initiator in no approver slot, approvers pairwise distinct, approval count ≥ `required_approvals`
5. Merkle inclusion of the receipt leaf against the checkpoint root, and the checkpoint signature against the trusted log key
6. `signed_at` / `committed_at` within `[issued_at, expires_at]`

Returns `{ valid, checks, errors, attestation, strict }` and fails closed on any missing input.

#### Strict verifier mode — *requires 1.5.0*

For deployment gates and hostile-environment verification, opt into strict mode:

```js
const r = verifyTrustReceipt(receipt, {
  approverKeys,
  logPublicKey,
  strict: true,
  rpId: 'www.emiliaprotocol.ai',
  expectedPolicyHash: 'sha256:...',
});
```

Strict mode preserves the frozen Section 6.3 `checks` object, then adds
`r.strict` as a second gate. When `strict: true`, `valid` requires both the base
checks and:

- `pinned_keys` — every signer and the log are locally pinned.
- `rp_id` — Class-A WebAuthn `rpIdHash` matches the caller-pinned RP ID.
- `user_presence` / `user_verification` — Class-A signoffs asserted UP + UV.
- `key_windows` — every approver key has parseable `valid_from` / `valid_to` and was valid at `issued_at`.
- `policy_hash` — every context matches `expectedPolicyHash`.
- `no_unsigned` — critical action, context, signoff, consumption, and log proof fields are present.

Without `strict: true`, `strict` is `{ enabled: false, valid: true, checks: {}, errors: [] }`, so existing verification and conformance semantics are unchanged.

#### Advisory: the PIP-007 initiator escalation attestation — *requires 1.4.0*

When the contexts carry a [PIP-007](https://github.com/emiliaprotocol/emilia-protocol/blob/main/PIPs/PIP-007-initiator-attestation.md) `initiator_attestation`, the result includes an **advisory** report:

```js
const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey });
r.attestation; // { present, consistent, issues: [] }
```

- `present` — a context carries an attestation.
- `consistent` — it is present in **every** context with an **identical** canonical form (the cross-context identity rule the protocol flags to catch a divide-and-misinform orchestrator showing different approvers different reasons).
- `issues` — any PIP-007 §1 malformations: unknown members, a `statement` over 280 characters, `escalation_trigger` of `policy_rule` without a `policy_basis`, or a bad enum value.

The advisory **never affects `valid` or any member of `checks`** — by design (PIP-007 §2): a receipt carrying a malformed attestation still verifies cryptographically, exactly as it does on a verifier that predates this PIP. The attestation is **a claim by the initiator** — identified but never trusted — so a policy engine MUST NOT use it to relax any check or raise any trust score.

### Federation (PIP-006) — *requires 1.3.0*

Cross-operator verification: accept a receipt issued by a different EP
operator using only its published discovery surfaces.

```js
import { verifyFederatedReceipt, verifyFederatedReceiptOffline } from '@emilia-protocol/verify';

// Online: resolves the issuer's keys from signature.key_discovery and
// checks its revocation surface.
const verdict = await verifyFederatedReceipt(receipt);
// { accepted, verified, revoked, signer, keyMatched: 'current'|'historical', checks }

// Air-gapped: supply the issuer's ep-keys.json + revocation set yourself.
const offline = verifyFederatedReceiptOffline(receipt, discoveryDoc, { revokedReceiptIds });
```

`resolveOperatorKeys(discoveryDoc, signerId)` is also exported (current keys
first, then `historical_keys` for rotation safety). See
`docs/FEDERATION-REGISTRY.md` for the operator discovery convention.

## Design Principles

- **Zero dependencies** — Only `node:crypto`. No supply chain risk.
- **Offline-first** — No network calls (the federation online path takes an injectable `fetch`). No EP server needed.
- **Deterministic** — Canonical JSON serialization for reproducible signatures.
- **Auditable** — A few small files, ~1,000 lines total. Read the entire thing in an hour.

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
