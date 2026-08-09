# EMILIA Verifier Attack Surface Map

Scope: the published `@emilia-protocol/verify` package (v3.20.1) — the offline
receipt verifier that anyone can run with no EP infrastructure. This document
maps the code paths that decide VERIFIED, for the purpose of bonding a public
forgery bounty. Companion: `BOUNTY-READINESS.md`; regression corpus:
`tests/verifier-forgery/`.

Base commit mapped: `origin/main` @ `6d7bc5d2` (worktree `verifier-hardening`).

## 1. Entry points (exact paths)

Source of truth is `packages/verify/src/*.ts`, compiled to
`packages/verify/dist/*.js`; the package-root `index.js` / `web.js` are thin
re-exports of the `dist` output. Published entry points (`package.json#exports`):

| Export | Source | Runtime | Verifies |
| --- | --- | --- | --- |
| `.` (`index.js`) | `src/index.ts` | Node `crypto` | everything below |
| `./web` (`web.js`) | `src/web.ts` | Web Crypto (`subtle`) | `verifyReceipt`, `verifyMerkleAnchor`, `verifyWebAuthnSignoff`, `verifyCommitmentProof`, `verifyReceiptBundle` |
| `./strict-json` | `src/strict-json.ts` | pure | canonicalization + gates |

The decision-making functions:

- **`verifyReceipt(doc, publicKeyBase64url, opts)`** — `src/index.ts:315`. Simple
  receipt: Ed25519 over the canonical `payload`, plus an optional Merkle anchor.
  This is the primitive the bond's simple-receipt claim rests on. Web mirror:
  `src/web.ts:179`.
- **`verifyTrustReceipt(receipt, opts)`** — `src/index.ts:1324`. The full I-D
  §6.3 six-step algorithm: recompute action hash; recompute each context hash and
  confirm it commits to the action; verify each signoff signature against the
  **pinned** approver key (Class B raw Ed25519, Class A WebAuthn P-256);
  separation-of-duties; Merkle inclusion + log-checkpoint signature; temporal
  windows. Plus opt-in additive gates (witness quorum, RFC 3161 timestamp,
  revocation, currency, consumption proof, initiator attestation, append-only
  consistency). This is where "the NAMED human signed that EXACT action" is
  actually established. Node-only — there is no web `verifyTrustReceipt`.
- **`verifyCommitmentProof`**, **`verifyReceiptBundle`**, **`verifyMerkleAnchor`**,
  **`verifyWebAuthnSignoff`** — supporting surfaces (both runtimes).

## 2. How a receipt is parsed and the signed message is reconstructed

The verifier consumes an **already-parsed JS object** (not raw JSON bytes). The
only raw-JSON surface is WebAuthn `clientDataJSON`, decoded with a fatal UTF-8
decoder and gated by `strictJsonGate` (`src/strict-json.ts:46`), which rejects
duplicate object member names, unpaired surrogates, and invalid syntax before
`JSON.parse`.

**Canonicalization** is `canonicalizeStrictJson` (`src/strict-json.ts`), a closed
I-JSON/JCS-equivalent profile shared byte-for-byte by Node and Web (both import
the same module). It operates on the parsed value and:

- sorts object keys; emits RFC 8785-equivalent bytes for the EP value subset;
- **refuses** non-plain objects (prototype check), sparse arrays, array holes,
  accessors, non-enumerable members, symbols, cycles, `undefined`/functions/
  `bigint`, non-finite numbers, and **non-safe-integer numbers** (the
  cross-language float hazard — decimals must be string-encoded);
- refuses malformed UTF-16 (unpaired surrogates) in strings and keys;
- enforces depth/node/string-byte limits.

The signed message:

- `verifyReceipt`: `SHA-nothing` — raw Ed25519 over `utf8(canonicalize(payload))`.
  `crypto.verify(null, payloadBytes, key, sig)`.
- `verifyTrustReceipt` step 1: `action_hash == sha256(canonicalize(action))`.
- step 2: `context_hash == sha256(canonicalize(context))`; each context must
  commit to `action_hash`; all contexts must share one `policy_hash`.
- step 3: signoff signature is over the **raw 32-byte context digest**
  (`Buffer.from(digestHex,'hex')`); Class A binds it as the WebAuthn challenge
  `b64u(digest)`.
- step 5b: checkpoint signature is Ed25519 over `sha256(canonicalize(checkpoint
  without log_signature))`.

Before any digest is folded, both `verifyReceipt` and `verifyTrustReceipt` run
the whole envelope through the canonical-profile gate (`isCanonicalizable`) and
fail closed on anything outside the profile — this defeats Proxy/accessor traps
and values that would disappear or serialize differently across languages.

## 3. Algorithm selection

There is **no algorithm negotiation from the document**. The verification
algorithm is pinned by the *key type*, not by `doc.signature.algorithm`:

- `verifyReceipt` calls `crypto.createPublicKey` on the pinned SPKI DER and
  **rejects any `asymmetricKeyType !== 'ed25519'`** (`src/index.ts:355`), then
  `crypto.verify(null, ...)`. The web mirror imports the key as `{name:'Ed25519'}`.
- Trust-receipt Class B uses raw Ed25519 (`crypto.verify(null,...)`, which only
  succeeds for Ed25519/Ed448 keys); Class A uses ECDSA P-256/SHA-256.
- The **pinned key class is authoritative**: a signoff cannot declare
  `key_class:'B'` to downgrade a pinned Class-A (WebAuthn) key to a bare
  signature (`src/index.ts:1569`).

`doc.signature.algorithm` is required-truthy but its *value is not consulted* —
it cannot cause a downgrade because the crypto is pinned by key type. See §5.

## 4. Key resolution and trust pinning

Keys are **always relying-party-supplied and pinned**; the verifier never
resolves a key from the document, from an embedded field, or from the network:

- `verifyReceipt(doc, publicKeyBase64url)` — the caller passes the exact key.
- `verifyTrustReceipt(receipt, { approverKeys, logPublicKey })` — approver keys
  are a pinned directory keyed by `approver_key_id`; the log key is pinned.
- **Identity join** (`src/index.ts:1499`): a pinned key entry must carry
  `approver_id`, and it must equal the context's `approver`. Without this, any
  pinned low-privilege key could sign a context that self-asserts a CFO/clinician
  approver. Missing or mismatched identity is a hard signature failure.
- **Compromise is terminal and retroactive** (`compromised_at`), independent of
  the presenter-claimed `issued_at` window (`src/index.ts:1519`).
- `base64url` decoding is strict/canonical on both runtimes (round-trip check),
  killing malleability via non-canonical encodings.

## 5. VERIFIED vs MATCH/SATISFIED/AUTHORIZED

The result deliberately separates cryptographic authenticity from admission:

- `verifyReceipt` → `{ valid, checks:{version,signature,anchor} }`.
- `verifyTrustReceipt` → `{ valid, checks:{...7 frozen steps}, decision_scope, ... }`.
  `decision_scope` is **always present** and states `authenticity_only:true`,
  `admission_authorized:false`, `replay_status:'not_evaluated'` unless a
  consumption proof is supplied. Advisory reports (`attestation`, PIP-007) never
  affect `valid`. This prevents an authenticity verdict being misread as
  executable authority or replay prevention.

## 6. One-time consumption

Offline verification does **not** enforce single-use by itself and never claims
to: `decision_scope.replay_status` stays `not_evaluated`. Opt-in
`opts.consumptionProof` (EP-SMT-CONSUME-v1) proves a nonce transitioned
absent→present once across two append-only-linked heads, and even then the result
is labelled `presented_consumption_proof_verified_not_atomic_admission`. Atomic
replay prevention is the enforcement point's job (the Gate), not the verifier's.

## 7. Findings from this pass

Two cross-runtime PARITY gaps were CONFIRMED and FIXED (see BOUNTY-READINESS.md
§Findings). Both concerned the *web* verifier being more permissive than Node on
inputs that neither treats as a valid authorization; no forgery (accepting a
signature the named signer did not produce over that exact action) was found in
either runtime. The full enumeration, with PoCs, is the regression corpus
`tests/verifier-forgery/forgery.test.mjs`.
