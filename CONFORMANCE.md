# EMILIA Protocol — Conformance

EMILIA is a *protocol*, not just a product: the value is that **anyone can
implement it and anyone can verify it, identically, with no EP server in the
trust path.** This document defines what a conformant implementation is and how
to prove it.

---

## 1. Authorization-receipt conformance (EP-RECEIPT-v1)

This is the core of the protocol: a signed, offline-verifiable authorization
receipt. An implementation is **EP-RECEIPT-v1 conformant** if, for every vector
in [`conformance/vectors/receipts.v1.json`](conformance/vectors/receipts.v1.json),
its verifier returns `expect.valid`.

The vectors are an adversarial battery — each one pins a single protocol
invariant:

| Class | Vectors |
|---|---|
| **accept** | minimal receipt · deeply-nested payload (recursive canonicalization) · key-order-independence · valid Merkle anchor |
| **reject** | unsupported version · missing signature · tampered payload · wrong key · malformed signature · tampered Merkle anchor |

### Three independent implementations, proven to agree

The repository ships three independent reference verifiers — written separately,
sharing no code:

| Language | Package |
|---|---|
| JavaScript / TypeScript | [`packages/verify`](packages/verify) (Node + `/web` Web Crypto build) |
| Python | [`packages/python-verify`](packages/python-verify) |
| Go | [`packages/go-verify`](packages/go-verify) |

Run the cross-language conformance suite — it feeds the **same** vectors through
all three and asserts they agree with each other and with the expected outcome:

```bash
node conformance/run.mjs
```

```
EP-RECEIPT-v1 conformance — vectors v1.0.0 (10 vectors)

  vector                          expect  JavaScript  Python      Go
  ────────────────────────────────────────────────────────────────────
  accept_minimal                  valid   ✓           ✓           ✓
  …
  reject_tampered_anchor          reject  ✓           ✓           ✓
  ────────────────────────────────────────────────────────────────────
  ✅ 10 vectors · 3 independent implementations agree (JavaScript, Python, Go)
```

This is the IETF bar for a real standard — **multiple independent interoperable
implementations** — and it runs on every push (CI job `conformance`). The
companion Internet-Draft is
[`draft-schrock-ep-authorization-receipts`](standards/).

### The format, in one paragraph

A receipt is `{ "@version": "EP-RECEIPT-v1", "payload": {…}, "signature":
{ "algorithm": "Ed25519", "value": <base64url> } }`, optionally with an
`anchor` (Merkle inclusion proof). Verification: (1) the version is recognized;
(2) the Ed25519 signature verifies over the **recursive key-sorted canonical
JSON** of `payload` (RFC 8785-style — sort keys at every depth, no whitespace);
(3) if an `anchor` is present, its proof folds the leaf hash through sorted-pair
SHA-256 steps to the claimed root. `valid = version ∧ signature ∧ (anchor ∈
{absent, true})`.

### Claiming conformance for a new implementation

1. Implement `verifyReceipt(document, publicKeyBase64url) → { valid }` for the
   format above.
2. Run your verifier against every vector in `receipts.v1.json`; return
   `expect.valid` for each.
3. Add a runner under `conformance/runners/` and wire it into `conformance/run.mjs`
   so your implementation is proven against the others on every push.

Conformance is self-certified against the published vectors. An implementation
that passes all vectors may state: **"EP-RECEIPT-v1 conformant — vectors v1.0.0."**

### Class A (device signoff) conformance

The Class-A WebAuthn device-signoff primitive (ECDSA P-256 over a
canonicalized authorization context) is verified by the JavaScript reference in
both Node and browser (Web Crypto) builds, proven byte-identical in
[`packages/verify/web.test.js`](packages/verify/web.test.js). Cross-language
signoff vectors (Python, Go) are the next conformance milestone; the receipt
format above is the stable, three-language interop surface today.

---

## 2. Legacy: scoring-layer conformance

The earlier trust-scoring layer (hashes, trust profiles, policy decisions) has
its own fixtures in `conformance/fixtures.json`, exercised by
`conformance/conformance.test.js` and `conformance/verify_hashes.py`.

| Level | Requirements |
|-------|-------------|
| **Hash-compatible** | All hash fixtures produce identical SHA-256 outputs |
| **Score-compatible** | All scoring fixtures produce outputs within ±0.1 tolerance |
| **Policy-compatible** | All policy fixtures produce identical Trust Decisions (allow/review/deny) |

### Scoring-layer invariants

1. **Hash determinism** — identical receipt inputs produce identical SHA-256 hashes regardless of language.
2. **Trust barrier** — pure unestablished volume cannot cross the establishment threshold.
3. **Policy monotonicity** — if an entity passes `strict`, it passes `standard`, `permissive`, and `discovery`.
4. **Appeal supremacy** — every negative trust effect must be challengeable.

---

## Reporting issues

If the reference implementations disagree, or contradict the spec, **that is a
bug worth a GitHub issue** — protocol correctness outranks backward
compatibility, and the cross-language suite exists precisely to catch it.
