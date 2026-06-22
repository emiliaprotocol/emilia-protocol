<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-TIME-ATTESTATION-v1 — independent, offline-verifiable proof of *when*

**Status:** Experimental — governed by an Extension PIP; additive over the core
protocol; not a production claim. Reference verifier:
`packages/verify/time-attestation.js` (with Python + Go parity); conformance
vectors: `conformance/vectors/time-attestation.v1.json` (JS/Python/Go agree).

## The gap this closes

An EP signoff's `issued_at` is asserted by whoever stamps it. For the **absolute
time** of a signoff or receipt to be trustworthy to a third party, an
**independent timestamping authority (TSA)** — a party EP *identifies but does not
trust* — signs over the hash of the artifact plus the time. This is the
trusted-time analogue of everything else in EP: **asymmetric, key-pinned,
fail-closed**.

It composes with the strong ordered quorum chain (`ordered_chain`,
`prev_context_hash`): the chain proves *relative order* cryptographically; a time
attestation **bounds the absolute instant**. Neither relies on an operator's
self-stamped clock.

## Wire format

```jsonc
{
  "@version": "EP-TIME-ATTESTATION-v1",
  "ts_authority_id": "ep:tsa:roughtime-1",   // the TSA (verifier pins its key)
  "hashed": "sha256:<hex>",                    // the artifact this attests to
  "time": "2026-06-20T12:00:00.000Z",          // RFC 3339 attested instant
  "proof": {
    "algorithm": "Ed25519",
    "ts_key_id": "tk1",
    "public_key": "<base64url SPKI DER>",
    "signature_b64u": "<base64url>"            // over the SIGNED_FIELDS below
  }
}
```

The TSA signature is over the canonical SIGNED_FIELDS
`{ @version, hashed, time, ts_authority_id }` (canonicalize() sorts keys), which
the verifier recomputes — so `time` or `hashed` cannot be swapped after signing.

## Verification (fail-closed)

`verifyTimeAttestation(att, opts)` returns `valid: true` only when **all** hold;
any gap yields `valid: false`:

1. **version** — `@version === "EP-TIME-ATTESTATION-v1"`.
2. **tsa_key_pinned** — `ts_authority_id` resolves to a key the verifier PINNED
   (`opts.tsaKeys`), and the proof's key equals the pinned key. An unpinned or
   self-asserted key confers nothing (identified-but-not-trusted).
3. **time_present** — `time` is a well-formed RFC 3339 instant.
4. **signature_valid** — the Ed25519 proof verifies, under the pinned key, over
   the verifier-recomputed SIGNED_FIELDS.
5. **hash_bound** *(when `opts.expectedHash` is supplied)* — the attested
   `hashed` equals the expected artifact hash.
6. **within_bounds** *(when `opts.notBefore` / `opts.notAfter` are supplied)* —
   the attested time falls within the window.

## Honest boundary — what this proves, and what it does not

A verified time attestation proves that **an independent, pinned authority
attested this exact content existed at time T.** It does **not** prove the TSA's
clock was correct, nor that no *earlier* attestation exists. It **bounds** the
time; it does not divine it. As with every EP artifact, the only added trust
input is one asymmetric signature by a named party the protocol pins — never a
symmetric secret (see the base draft, "No symmetric key on the verification
trust path").
