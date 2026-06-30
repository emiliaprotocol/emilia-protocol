# EP-RECEIPT-v1 conformance vectors

`receipts.v1.json` is the canonical, adversarial test-vector battery for the
EMILIA Protocol authorization-receipt format. Every EP-conformant verifier MUST
return each vector's `expect.valid`.

- **Self-contained:** each vector carries its own `public_key` (base64url SPKI)
  and `document`. No EP server, no shared state.
- **Adversarial:** the `reject` vectors each pin one invariant (tamper, wrong
  key, replay-by-version, malformed signature, broken Merkle anchor, …).
- **Deterministic:** regenerate byte-identically with `node generate.mjs`
  (fixed Ed25519 seeds).

Run the cross-language suite (JavaScript + Python + Go must all agree):

```bash
node conformance/run.mjs     # or: npm run conformance
```

Format, claiming conformance, and adding a new-language implementation:
see [`../../CONFORMANCE.md`](../../CONFORMANCE.md).

## `jws.json` — EP-RECEIPT-JWS-PROFILE-v1

`jws.json` carries vectors for the OPTIONAL JWS (RFC 7515) serialization of EP
receipts — see [`../../docs/EP-RECEIPT-JWS-PROFILE.md`](../../docs/EP-RECEIPT-JWS-PROFILE.md).
Each vector is a compact JWS over the JCS-canonical bytes of an `EP-RECEIPT-v1`
payload, signed `EdDSA`/Ed25519 (RFC 8037). A conformant verifier — EP-native or
any standard JOSE library — MUST return each vector's `expect.valid`. The
reference verifier is `verifyReceiptJws` in
[`../../packages/require-receipt/jws.js`](../../packages/require-receipt/jws.js);
`jose`-library cross-verification is proven in that package's `jws.test.js`.
Regenerate byte-identically with `node generate-jws.mjs` (fixed Ed25519 seeds,
same canonical signer as `receipts.v1.json`).
