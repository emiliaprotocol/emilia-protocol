<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-EVIDENCE-RECORD-v1 — long-term, crypto-agile preservation of EP evidence

**Status:** Experimental — governed by an Extension PIP; additive over the core
protocol. Reference verifier: `packages/verify/evidence-record.js` (with Python +
Go parity); conformance vectors: `conformance/vectors/evidence-record.v1.json`
(JS/Python/Go agree). Approach follows IETF **RFC 4998 (Evidence Record Syntax)**.

## The gap this closes

An EP receipt is meant to "verify years — even decades — later," and the GAGAS /
GAO Green Book / Uniform Guidance mapping cites government retention of **10-25+
years**. But any fixed algorithm (Ed25519 signatures, SHA-256 hashing) weakens
over that horizon: a receipt perfectly verifiable today could become forgeable
before its retention period ends. EP had no answer for algorithm aging. This
profile provides one, using the long-established RFC 4998 approach.

## The mechanism — a renewal chain

An evidence record protects an artifact (typically a receipt) by a **chain of
renewals**. Each renewal is an EP-TIME-ATTESTATION-v1 (independent, key-pinned,
offline) that re-timestamps the *previous* attestation under a possibly
**stronger** hash, BEFORE the older algorithm is broken:

```jsonc
{
  "@version": "EP-EVIDENCE-RECORD-v1",
  "protected_hash": "sha256:<hex>",          // hash of the protected artifact
  "archive_timestamps": [
    { "time_attestation": { /* EP-TIME-ATTESTATION-v1, hashed = protected_hash */ } },
    { "time_attestation": { /* hashed = sha384(canonical(previous attestation)) */ } },
    ...                                        // add a renewal under a fresh alg as needed
  ]
}
```

Because renewal *i* covers the entire prior attestation, the chain proves the
artifact has been continuously, independently time-anchored from its first
attestation to the latest renewal — even across a change of hash algorithm
(sha256 -> sha384 -> ...). This is RFC 4998's "Archive Timestamp Chain" idea
expressed in EP's asymmetric, pinned-authority, offline style.

## Verification (fail-closed)

`verifyEvidenceRecord(record, opts)` returns `valid: true` only when all hold:

1. **version** — `@version === "EP-EVIDENCE-RECORD-v1"`.
2. **protected_bound** *(when `opts.protectedHash` supplied)* — `protected_hash`
   equals the hash of the artifact the relying party independently holds.
3. **chain_nonempty** — at least one archive timestamp.
4. **all_timestamps_valid** — every renewal's EP-TIME-ATTESTATION verifies under a
   pinned TSA.
5. **chain_linked** — the first renewal covers `protected_hash`; each later
   renewal's `hashed` equals the (alg-agile) hash of the previous attestation.
6. **monotonic_time** — renewal times strictly increase.

Supported renewal hash algorithms: SHA-256, SHA-384, SHA-512.

## Honest boundary

A valid evidence record proves the artifact was **continuously time-anchored by
independent, pinned authorities** across the renewal chain. It does not prove the
artifact was *correct*, nor that each renewal actually occurred before the prior
algorithm was broken in the wild — that is an operational discipline the chain
*records* (and a relying party can audit), not one verification can divine. As
with every EP artifact, the only added trust input is asymmetric signatures by
named, pinned authorities — never a symmetric secret.
