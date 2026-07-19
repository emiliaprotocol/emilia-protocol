# Build / Binary Attestation — staging + honesty boundary

Closes DoD-audit **GAP 5 (build/binary attestation)** at the software-verifier
level. The reproducible-build → transparency-log links and a strict TPM 2.0
quote verifier are real and tested. The checked-in quote was produced by
`tpm2-tools` against `swtpm`; it proves wire-level interoperability, not that a
physical production host runs the attested binary. No physical TPM, manufacturer
EK chain, measured-boot deployment, or production quote is claimed.

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
| **(1) Reproducible build → binary hash** | ✅ real, tested | `npm run release:verify:reproducible` builds `packages/verify` twice from canonicalized input and refuses on byte drift. The live attestation path additionally refuses unless the worktree is clean and checked-out HEAD exactly equals the attested source commit. |
| **(2) Binary hash → transparency-log leaf** | ✅ real, tested | `attestation/merkle-log.js` builds an EP-MERKLE-v2 leaf `SHA-256(0x00 ‖ JCS(subject))` and an inclusion proof accepted by `verifyMerkleAnchor(..., { v2: true })` from `@emilia-protocol/verify`. Multi-leaf inclusion covered in the test suite. |
| **(3) Leaf binding (source+binary → leaf)** | ✅ real, tested | The leaf commits to `{source_commit, package_path, artifact_filename, artifact_sha256}`. Flip any field and the leaf changes; a lifted proof from another build is rejected fail-closed (`build-attestation.test.js`). |
| **(4a) Verifier: H == build(source)** | ✅ real, tested | `verifyBuildAttestation(record, { rebuild })` runs the reproducible build and rejects (`rebuild_mismatch`) if the claimed binary hash is not the deterministic build of the pinned source. |
| **(4b) Verifier: L ∈ log under root R** | ✅ real, tested | Inclusion proof reconstructs the claimed root; a tampered root/proof is rejected (`log_inclusion_failed`). Optional signed checkpoint's `root_hash` must equal the inclusion root. |
| **(4c) TPM quote verifier** | ✅ real, tested against software-TPM evidence | `verifyTpm2Quote()` parses the official TPM 2.0 structures and fails closed unless verifier nonce, exact PCR selection, known-good PCR values and composite, quote signature, safe clock, and pinned AK SPKI all match. |

All fail-closed paths are exercised: malformed record, tampered hash, tampered
root, lifted proof, throwing rebuild, non-hex rebuild, checkpoint mismatch, and a
rejecting TPM verifier all return `{ valid: false, reason }` — none throw on
adversarial input.

Run it:

```bash
node attestation/verify-cli.mjs demo packages/verify      # determinism proof + full software chain
node attestation/verify-cli.mjs emit packages/verify > rec.json
node attestation/verify-cli.mjs verify rec.json --rebuild  # live rebuild link
npx vitest run attestation/build-attestation.test.js attestation/tpm-quote-verifier.test.js
```

## What remains HARDWARE-GATED

`record.tpm_quote` is an optional `EP-TPM-QUOTE-v1` field.
`verifyBuildAttestation()` refuses to treat it as verified unless a verifier is
injected. The repository supplies that verifier in `tpm-quote-verifier.js`; a
deployment must inject it with verifier-owned nonce, AK fingerprints, PCR
selection, and known-good PCR values. A present-but-unverified quote never
contributes a passing TPM verdict, and a rejected quote fails the record closed.

A real physical deployment still needs, on the build/runtime host:

1. A **TPM 2.0** (discrete or firmware) with an **Endorsement Key (EK)** and an
   enrolled **Attestation Key (AK)**, plus the EK certificate the buyer trusts.
2. A **measured boot / IMA** path that measures the binary `H` into a PCR, so the
   quoted PCR value is a function of what actually loads.
3. A `TPM2_Quote` over that PCR set with the record's **nonce** for freshness,
   signed by the AK; verification of the AK→EK chain to the buyer's trust root.
4. Supplying the resulting `EP-TPM-QUOTE-v1` evidence to
   `verifyTpm2Quote()` under verifier-selected trust inputs.

None of (1)–(3) exists in this CI/dev environment. The software-TPM fixture has
an AK and real quote signature but no physical-hardware or manufacturer trust
property, so physical evidence remains **pending: hardware-required**.

## What a defense buyer completes

- Run the reproducible build on their own runner (or reproduce it) to independently
  reach `H` from the pinned commit.
- Operate (or point at) a persistent, checkpointed, **witness-cosigned** log
  (`witness/`, `docs/security/TRANSPARENCY-LAYER-DESIGN.md`) rather than the
  in-memory reference builder, and carry the signed checkpoint in `log_entry.checkpoint`.
- Provision TPM AK/EK enrollment, measured boot/IMA, known-good PCR policy, and
  a fresh quote. Then inject `verifyTpm2Quote` into
  `verifyBuildAttestation` to verify all four links end to end.

## Honest claim inventory

- **PROVEN:** the rebuild is tied to the exact clean checked-out source commit;
  the log leaf binds source+binary; inclusion and rebuild links verify and fail
  closed; the TPM adapter verifies real TPM wire structures, nonce, PCR policy,
  signature, and pinned AK against a software-TPM fixture.
- **NOT PROVEN / NOT CLAIMED:** that a physical production TPM attests the
  running binary, that an AK chains to a trusted manufacturer EK, or that a
  measured-boot policy is deployed. Do not market software-TPM interoperability
  as physical-hardware attestation.
