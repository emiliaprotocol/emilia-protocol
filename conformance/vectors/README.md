# EP-RECEIPT-v1 conformance vectors

`model-to-matter.v1.json` is the deterministic executor-side clearance and
effect-statement suite for the Model-to-Matter profile. Regenerate it with
`node conformance/vectors/generate-model-to-matter.mjs` and execute it with
`npm run m2m:conformance`. It deliberately claims neither biological screening,
scientific safety, nor physical truth.

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

## `succession-authorization-binding.v1.json` — cross-format succession binding

This small vector checks a succession receipt's optional `authorization_binding`
claim against a derived CAID and canonical authorization-receipt hash. Native
verification of both formats is an explicit precondition: the fixture does not
verify signatures, freshness, audience, succession state, or replay state. It
therefore demonstrates internal binding consistency after native verification;
it does not independently prove cross-format composition, turn a succession
receipt into authorization, or make an absent optional claim invalid.

## `aeb-audit-provenance-join.v1.json` — staged composition profile

This synthetic opaque-reference fixture checks the narrow join between an AEB
decision and an AUDIT-shaped record carrying C2PA, OTEL, and SCITT references.
It derives and parses the CAID and binds the exact session, provenance-reference
set, and outcome label. It does not parse or natively verify those external
formats and makes no claim of C2PA, AUDIT, OTEL, or SCITT conformance.

## Opt-in profile suites (cross-language)

Five opt-in verify profiles ship shared, cross-language vector suites that the
JavaScript, Python, and Go verifiers all run in `conformance/run.mjs` and must
agree on. The first four regenerate byte-identically with
`node generate-optin-profiles.mjs` (fixed Ed25519 seeds for the witness
cosignatures); the timestamp-proof suite is minted separately (see below):

- `currency.v2.json` — **EP-CURRENCY-v1**: valid iff
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
- `timestamp-proof.v1.json` — **EP-TIMESTAMP-PROOF-v1** (RFC 3161): valid iff
  `verifyTimestampProof(timestamp_proof, expected_digest, pinned_tsa_keys).verified`.
  An INDEPENDENT proof of WHEN: a pinned external TSA's `TimeStampToken` (CMS
  SignedData carrying a TSTInfo) over the caller's expected digest, fail-closed on
  any refusal (unpinned TSA, digest mismatch, wrong pinned key, tampered
  signature, non-SignedData, unparseable token). The JS minimal DER/CMS reader was
  ported faithfully to pure Python (with `cryptography` used only for the
  RSA/ECDSA signature verify, so no new dependency) and pure-stdlib Go, so all
  three lanes agree over real `openssl`-minted tokens. Regenerate with
  `node generate-timestamp-proof.mjs` (mints a fresh local test TSA + tokens and
  self-checks against the JS reference before writing; requires `openssl` on
  PATH). The suite is self-contained: the signer SPKI (pinned key) and a decoy
  SPKI are embedded per vector, so no key material lives outside the file.
