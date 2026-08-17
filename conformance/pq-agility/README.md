# EP-SIG-AGILITY-v1 conformance vectors

Deterministic vectors proving signature-algorithm agility for EP evidence:
the SAME canonical receipt payload bytes are signed under Ed25519 and under
ML-DSA-65 (FIPS 204), and both signatures verify over identical content. A
verifier that passes this suite demonstrates that the algorithm is an
explicit, checked field over unchanged canonical bytes, not a fork of the
artifact format.

Why this exists: authorization evidence has a decades-long verification
horizon (disputes, statutes of limitations, 10-25+ year government retention
schedules). An Ed25519 receipt signed today must still be trustworthy
testimony in 2035. Algorithm agility, plus re-attestation before an old
algorithm breaks (see `packages/verify/src/evidence-record.ts`,
EP-EVIDENCE-REATTESTATION-v1), is how evidence outlives algorithms.

## Files

- `vectors.json` -- the vector set. Verified end to end by
  `packages/verify/pq-signature-agility.test.ts`
  (run: `npx tsx --test packages/verify/pq-signature-agility.test.ts`).

## Determinism and key provenance (TEST KEYS ONLY)

Every byte in `vectors.json` is reproducible from fixed public seed labels.
Never use these keys or seeds for anything real.

- Canonicalization: the EP JCS-style `canonicalize()` from
  `@emilia-protocol/verify` (`packages/verify/src/index.ts`). The message
  bytes are the UTF-8 encoding of the canonical form of `payload` -- the
  same bytes the existing EP-RECEIPT-v1 Ed25519 path signs.
- Ed25519: private key seed = `SHA-256("EP-SIG-AGILITY-v1/vectors/ed25519/1")`,
  wrapped in the RFC 8410 PKCS8 prefix
  `302e020100300506032b657004220420`. Ed25519 signatures are deterministic
  per RFC 8032, so the signature bytes are fixed by seed + payload.
- ML-DSA-65: keygen seed = `SHA-256("EP-SIG-AGILITY-v1/vectors/ml-dsa-65/1")`,
  expanded by ML-DSA.KeyGen (FIPS 204). Signing uses the FIPS 204
  deterministic variant (`extraEntropy = false`), so the 3309-byte signature
  is likewise fixed by seed + payload.
- The checked-in vectors were generated with `@noble/post-quantum` 0.6.1.
  The current 0.7.0 verifier accepts the same bytes. Both are pure-JS FIPS 204
  implementations from the same project. Per its own README the project has
  not completed an independent audit and is not FIPS validated; these vectors
  demonstrate format-level algorithm agility and cross-version verification,
  not a certification claim.

## Vector semantics

| id | expectation |
| --- | --- |
| `ed25519-valid` | verifies |
| `ml-dsa-65-valid` | verifies (same canonical bytes as the Ed25519 vector) |
| `ed25519-tampered-signature` | refusal, reason `signature_invalid` |
| `ml-dsa-65-tampered-signature` | refusal, reason `signature_invalid` |
| `unknown-algorithm-refused` | refusal, reason `unknown_algorithm` (an unknown algorithm never verifies; INDETERMINATE never authorizes) |
| `hybrid-all-valid` | both signatures over the same bytes; verifies under policy `hybrid_all` |
| `hybrid-all-stripped-pq-leg-refused` | refusal, reason `missing_required_algorithm` (the required set defaults to the full registry and never narrows itself to what was presented) |
| `per-algorithm-never-collapses` | top-level verdict `null`; per-algorithm verdicts reported separately and never collapsed |

## Honest boundary

The `hybrid_all` policy here is relying-party policy over presented
signatures; the signatures do not cryptographically commit to the algorithm
set. For an envelope whose signatures themselves commit to the full set
(anti-stripping), see EP-HYBRID-v1 (`packages/verify/src/pq-hybrid.ts`).
Agility protects artifacts signed from now on; it does not retroactively
protect an already-issued single-algorithm artifact. That requires
re-attestation while the old algorithm is still unbroken.
