# Build / Binary Attestation — staging + honesty boundary

Closes DoD-audit **GAP 5 (build/binary attestation)** at the software level. This
is a **STAGE-track** deliverable: the reproducible-build → transparency-log links
are real and tested; the TPM 2.0 hardware link is defined but **not** implemented,
because it requires physical hardware not present in CI/dev. Nothing here fires an
outbound or claims TPM attestation works.

## The chain

```
pinned source commit
   └─(1) reproducible build ──▶ deterministic binary hash H
         └─(2) append to transparency log ──▶ leaf L, inclusion proof, root R
               └─(3) TPM 2.0 quote ──▶ "the host that runs H measured H into a PCR"
                     └─(4) verifier ──▶ H == build(source) AND L∈log AND H is what runs
```

## What is REAL and TESTED here

| Link | Status | Evidence you can re-run |
| --- | --- | --- |
| **(1) Reproducible build → binary hash** | ✅ real, tested | `npm run release:verify:reproducible` builds `packages/verify` twice from a canonicalized input and refuses on byte drift. Two independent runs both produce `sha256 bf97b1646ca587df2824c9573896d6e69b6a3c59423108f16c44c9abb1fd571b` (at commit `1a2293e8`, `@emilia-protocol/verify@3.11.0`). |
| **(2) Binary hash → transparency-log leaf** | ✅ real, tested | `attestation/merkle-log.js` builds an EP-MERKLE-v2 leaf `SHA-256(0x00 ‖ JCS(subject))` and an inclusion proof accepted by `verifyMerkleAnchor(..., { v2: true })` from `@emilia-protocol/verify`. Multi-leaf inclusion covered in the test suite. |
| **(3) Leaf binding (source+binary → leaf)** | ✅ real, tested | The leaf commits to `{source_commit, package_path, artifact_filename, artifact_sha256}`. Flip any field and the leaf changes; a lifted proof from another build is rejected fail-closed (`build-attestation.test.js`). |
| **(4a) Verifier: H == build(source)** | ✅ real, tested | `verifyBuildAttestation(record, { rebuild })` runs the reproducible build and rejects (`rebuild_mismatch`) if the claimed binary hash is not the deterministic build of the pinned source. |
| **(4b) Verifier: L ∈ log under root R** | ✅ real, tested | Inclusion proof reconstructs the claimed root; a tampered root/proof is rejected (`log_inclusion_failed`). Optional signed checkpoint's `root_hash` must equal the inclusion root. |

All fail-closed paths are exercised: malformed record, tampered hash, tampered
root, lifted proof, throwing rebuild, non-hex rebuild, checkpoint mismatch, and a
rejecting TPM verifier all return `{ valid: false, reason }` — none throw on
adversarial input.

Run it:

```bash
node attestation/verify-cli.mjs demo packages/verify      # determinism proof + full software chain
node attestation/verify-cli.mjs emit packages/verify > rec.json
node attestation/verify-cli.mjs verify rec.json --rebuild  # live rebuild link
npx vitest run attestation/build-attestation.test.js       # 25 tests
```

## What is HARDWARE-GATED (not done here)

**Link (3), the TPM 2.0 quote.** `record.tpm_quote` is an **optional** field of
format `EP-TPM-QUOTE-v1`. `verifyTpmQuote()` is a clearly-marked stub that
**refuses by default** with `tpm-hardware-required`. Its interface accepts an
injected `hardwareVerifier` so a real one drops in without changing the record
format or the chain. A present-but-unverified quote never contributes a passing
verdict; an injected verifier that *rejects* fails the record fail-closed.

A real implementation needs, on the build/runtime host:

1. A **TPM 2.0** (discrete or firmware) with an **Endorsement Key (EK)** and an
   enrolled **Attestation Key (AK)**, plus the EK certificate the buyer trusts.
2. A **measured boot / IMA** path that measures the binary `H` into a PCR, so the
   quoted PCR value is a function of what actually loads.
3. A `TPM2_Quote` over that PCR set with the record's **nonce** for freshness,
   signed by the AK; verification of the AK→EK chain to the buyer's trust root.
4. Wiring `hardwareVerifier` (e.g. `tpm2-tools`, Go `go-attestation`,
   `tpm2-pytss`) to return `{ ok, pcrDigest }`.

None of (1)–(3) exists in this CI/dev environment (no TPM, no EK cert, no AK
enrollment), so this link is honestly left **pending: hardware-required**.

## What a defense buyer completes

- Run the reproducible build on their own runner (or reproduce it) to independently
  reach `H` from the pinned commit.
- Operate (or point at) a persistent, checkpointed, **witness-cosigned** log
  (`witness/`, `docs/security/TRANSPARENCY-LAYER-DESIGN.md`) rather than the
  in-memory reference builder, and carry the signed checkpoint in `log_entry.checkpoint`.
- Provision TPM AK/EK enrollment and supply a `hardwareVerifier`, at which point
  `verifyBuildAttestation` verifies all four links end-to-end.

## Honest claim inventory

- **PROVEN:** the reproducible build is deterministic (two identical hashes, quoted
  above); the log leaf binds source+binary; inclusion and rebuild links verify and
  fail closed.
- **NOT PROVEN / NOT CLAIMED:** that any TPM attests the running binary. No TPM was
  present; the quote path is a stub. Do not represent TPM attestation as working.
