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

## `canonicalization.v1.json` — EP-CANONICALIZATION-v1

Differential canonicalization-malleability battery: raw JSON texts that pin
RFC 8785 / I-JSON behavior byte-for-byte across the JavaScript, Python, and Go
lanes (Unicode normalization non-application, escape aliases, UTF-16 member
sort, duplicate member names, unpaired surrogates, number-token aliases, a
pinned nesting bound of 64). Accept vectors carry a pinned SHA-256 of the
canonical bytes. The duplicate-name, surrogate, and depth gates are enforced at
the parse boundary of each runner (see `../runners/strict-json.mjs` for the
shared contract); the profile predicate, canonicalization, and digests exercise
the verify packages. Regenerate with `node generate-canonicalization.mjs`.

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

## Opt-in profile suites (cross-language)

Four opt-in verify profiles ship shared, cross-language vector suites that the
JavaScript, Python, and Go verifiers all run in `conformance/run.mjs` and must
agree on. Regenerate all four byte-identically with
`node generate-optin-profiles.mjs` (fixed Ed25519 seeds for the witness
cosignatures):

- `currency.v1.json` — **EP-CURRENCY-v1**: valid iff
  `evaluateCurrency(currency.args).currency_at_T.status === currency.expect_status`.
  Pins the two-valued authentic-as-of-commit vs currency-at-T result; `unknown`
  is the honest offline default (offline verification can NEVER prove currency).
- `initiator-attestation.v1.json` — **EP-INITIATOR-ATTESTATION-v1**: valid iff
  `validateInitiatorAttestation(initiator_attestation).ok`. Fail-closed field
  validation plus hostile-text neutralization (bidi / C0-C1 / zero-width escaped,
  codepoint-capped, homoglyph/mixed-script flagged).
- `consumption-proof.v1.json` — **EP-SMT-CONSUME-v1**: valid iff
  `verifyConsumptionProof(consumption_proof).valid`. Sparse-Merkle-over-nonce
  one-time consumption (absent → present transition on an append-only tree).
- `witness.v1.json` — **EP-WITNESS-v1**: valid iff
  `requireWitnessQuorum(witness_quorum.checkpoint, witness_quorum.cosignatures,
  witness_quorum.pinned, witness_quorum.k).ok`. k-of-n distinct pinned witnesses
  cosigning one checkpoint head (seeded Ed25519; the same committed bytes verify
  in all three languages).

A fifth opt-in profile, **timestamp-proof (RFC 3161)**, is a **JavaScript-only**
reference verifier: its Python and Go ports were deferred (no CMS/PKCS#7
SignedData parser in the Python `cryptography` dependency or the zero-dependency
Go module), so it has no cross-language vector suite here. See
[`../../CONFORMANCE.md`](../../CONFORMANCE.md).
