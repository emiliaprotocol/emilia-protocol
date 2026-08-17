<!-- SPDX-License-Identifier: Apache-2.0 -->
# Encoding-equivalence profile (EP-COSE-ENCODING-v0.1)

Status: encoding profile and vector suite. It confers no trust. The receipt
verifies under its own Ed25519 signature over its canonical JSON bytes; the
COSE envelope is a registration/transport form. Nothing in this profile
changes what any signature proves, who is trusted, or what is authorized.

## What the vectors prove

One EP receipt (`EP-RECEIPT-v1`), fixed test keys, byte-exact artifacts in
`vectors.json`:

1. **The CAID join survives re-encoding.** The CAID is a digest of the
   action object's canonical JCS bytes (`jcs-sha256` suite), so it is
   byte-identical whether the receipt travels as canonical JSON, as a
   deterministic CBOR map, or inside a COSE_Sign1 envelope. The vectors pin
   the identical `caid:` string across all three forms, cross-checked against
   the reference implementation in `caid/impl/js/caid.mjs` under the registry
   definition for `payment.release.1`.
2. **The COSE payload IS the canonical JSON bytes.** SHA-256 of the receipt's
   canonical JSON equals SHA-256 of the COSE_Sign1 payload, so the receipt's
   original signature keeps verifying over exactly the carried bytes. Wrapping
   and unwrapping the envelope is transport, not transformation.
3. **The CBOR mapping round-trips.** JSON -> deterministic CBOR -> JSON
   recanonicalizes to the identical JCS bytes and re-encodes to the identical
   CBOR bytes.
4. **Fail-closed against encoding games.** A CBOR encoding of the SAME
   content with unsorted map keys, a non-shortest integer, or an
   indefinite-length header is refused with the named reason
   `non_deterministic_encoding`, never accepted as semantically equal. A
   tampered payload under intact headers is refused
   (`envelope_signature_invalid`) before the receipt is ever read.

This produces a valid deterministic COSE_Sign1 transport envelope for EP
evidence, without changing any trust semantics. It is NOT a complete SCITT
Signed Statement per RFC 9943: that requires additional protected-header
semantics, including CWT Claims, which this transport envelope does not carry.
That profile exists separately as EP-SCITT-STATEMENT-v1
(packages/verify/src/scitt-statement.ts, vectors and RFC requirement table in
conformance/scitt-statement/). No Transparency Service has accepted an
EP-SCITT-STATEMENT-v1 statement; registration remains a separate, gated step.

## Field-mapping choice: text keys

The receipt-to-CBOR mapping is the identity mapping from the EP strict-JSON
domain (strings, booleans, null, safe integers, arrays, plain objects) onto
the corresponding CBOR subset, with TEXT map keys. Integer-key compression
was rejected because the EP receipt payload is an open strict-JSON document
domain: a closed integer-key table cannot be total over it without freezing
the payload schema, and a partial mapping would silently drop exactly the
fields a dispute turns on. Text keys keep the mapping total, bijective on the
domain, and auditable byte-for-byte.

## Envelope choice: transport, not re-signature

The COSE_Sign1 (RFC 9052, tag 18) payload is the receipt's canonical JSON
bytes. Protected headers carry `alg` EdDSA (1: -8), the content type
(3: `application/emilia-receipt+json`), a `kid` (4), and the private text
label `ep.caid` with the action's CAID string.

The trust consequence, stated plainly: the COSE signature is a NEW
attestation by whoever holds the envelope key. It says "this key holder
submitted these bytes", nothing more. It is not the approval signature and
must never be credited as one. Approval is proven only by the receipt's own
signature inside the payload, verified under the relying party's pinned
issuer key. The verifier in
`packages/verify/src/receipt-cose-encoding.ts` therefore requires BOTH pins
and reports the two signatures as separate checks.

The alternative profile, re-signing a CBOR-mapped receipt so the COSE leg is
a first-class receipt encoding, would mint a second first-class attestation
whose signer and trust root need their own pinning story. It is deliberately
not implemented here and is recorded as future work.

## Two crypto tracks, kept separate

Do not conflate the two COSE signature tracks in this repository:

- This generic receipt COSE envelope signs with **EdDSA (Ed25519)** only
  (protected header `alg` = -8). It is a transport/registration envelope over
  the receipt's canonical JSON bytes.
- **ML-DSA-65 COSE** (the post-quantum, FIPS 204 signature) lives ONLY in the
  McGraw delegation adapter (`packages/verify/src/aeb-mcgraw-delegation-adapter.ts`).
  It is not part of this profile.

The only thing the two share is the deterministic CBOR encoding rule (RFC 8949
Section 4.2.1). They do not share signature algorithms, keys, or trust roots.

## The deterministic ordering shipped (verified by experiment)

Map keys are sorted in the **bytewise lexicographic order of the
deterministic encodings of the keys** (RFC 8949 Section 4.2.1), NOT the older
RFC 7049 Section 3.9 length-first ordering. This exact ambiguity is a known
interop trap, and the vectors exist to nail it. Experiments run on Node
v26.5.0 against the repository's installed libraries before shipping:

- `cbor` (10.0.12): unusable on this Node version. Every encode returns only
  the first byte (`cbor.encode(1000)` returns `19` instead of `1903e8`;
  decoding its own output fails with "Insufficient data").
- `cbor-x` (1.6.5): encodes a 2-entry object map with a 16-bit length header
  (`b90002...` instead of `a2...`), violating shortest-form lengths, and
  wraps JS Maps in tag 259. Its DECODER also accepts non-shortest integers
  (`19000a` decodes to 10), so it cannot serve as the strict gate.
- The in-repo McGraw adapter codec
  (`packages/verify/src/aeb-mcgraw-delegation-adapter.ts`,
  `encodeDeterministicCbor`) now implements the SAME RFC 8949 Section 4.2.1
  bytewise-encoded-key ordering as this profile. It was historically RFC 7049
  Section 3.9 length-first; the two orders coincide for its own small positive
  integer COSE labels but diverge in general, and that historical divergence is
  preserved as a regression test in the McGraw suite
  (`packages/verify/aeb-mcgraw-delegation-adapter.test.ts`, "deterministic CBOR
  map order is RFC 8949 bytewise, not RFC 7049 length-first"). Worked example,
  the map `{100: "c", -1: "b"}`: RFC 8949 requires `a218646163206162` (key
  `100`, encoded `0x1864`, first because `0x18 < 0x20` bytewise), whereas the
  retired RFC 7049 length-first order put key `-1` (encoded `0x20`, shorter)
  first (`a220616218646163`).

So this profile ships its own encoder and strict decoder
(`encodeDeterministicCbor8949` / `decodeDeterministicCbor8949`), inline and
dependency-free. It stays separate from the McGraw codec not because the
orderings differ (they no longer do) but because it is a Result-typed API with
its own strict decoder. The test suite uses `cbor-x` only as an independent
decoder cross-check that the deterministic bytes carry the intended values.

A concrete divergence the vectors pin: JCS orders object members by UTF-16
code units, so the canonical JSON of the test receipt starts with
`{"@version":...}`. RFC 8949 orders map keys by the bytes of their encoded
form, and the 7-byte key `payload` (header `0x67`) sorts before the 8-byte
`@version` (header `0x68`), so the deterministic CBOR map starts with the
`payload` entry. Equivalence in this profile is at the VALUE level: each
encoding applies its own deterministic order, decoding recovers the identical
value, and the CAID digest is computed over the JCS bytes in both worlds.

## Run it

```bash
npx vitest run tests/receipt-cose-encoding.test.ts
```

The suite regenerates every artifact from the recorded test seeds (Ed25519
signing is deterministic) and asserts byte equality against `vectors.json`,
runs the hostile vectors, and exercises the fail-closed edges (wrong keys,
non-canonical payload JSON, mismatched CAID header, untagged envelope, junk
input).

## Limits (what this profile does not prove)

- VERIFIED here means the cryptographic checks pass under the two keys the
  caller pinned. It is never ACCEPTED: whether either key is trusted is a
  relying-party decision this profile does not make.
- The envelope signature proves submission of bytes by the envelope key
  holder. It proves nothing about approval, authorization, execution, or
  outcome.
- The CAID helper in this module checks the action-type grammar and the
  canonicalization domain only; material-field validation against a pinned
  type definition is the CAID core's job (`caid/impl`, `caid/DESIGN.md`).
- The keys in `vectors.json` are test keys derived from public seed strings.
  They authenticate nothing.
- Registration of such an envelope on an actual SCITT transparency service,
  and the service's own receipt semantics, are out of scope here; see
  `examples/scitt/` for the seam vectors.
