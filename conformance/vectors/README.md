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
