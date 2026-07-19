# `attestation/` — EP build / binary attestation (GAP 5)

Software chain that ties a **pinned source commit** to a **deterministic binary
hash**, records that hash in an **EP-MERKLE-v2 transparency log**, and verifies the
whole thing offline. The final **TPM 2.0** link (proving the measured binary is
what a host actually runs) is defined but hardware-gated — see
[`STAGING.md`](./STAGING.md) for the exact boundary and the honest claim inventory.

| File | Role |
| --- | --- |
| `build-attestation.js` | Record format `EP-BUILD-ATTESTATION-v1` + fail-closed `verifyBuildAttestation()`; leaf binding, log inclusion (reuses `verifyMerkleAnchor`), optional live rebuild, optional TPM stub. |
| `merkle-log.js` | Reference EP-MERKLE-v2 log builder: leaf hashing + inclusion proofs accepted by the production verifier. |
| `reproducible-rebuild.mjs` | The live rebuild link. It fails closed unless the worktree is clean and HEAD exactly equals the attested commit, then wraps `scripts/verify-reproducible-package.mjs`. |
| `verify-cli.mjs` | `emit` / `verify` / `demo` CLI. |
| `build-attestation.test.js` | 25 vitest cases: happy path, multi-leaf inclusion, every fail-closed path, TPM boundary. |
| `tpm-quote-verifier.js` | Strict TPM 2.0 `TPMS_ATTEST` adapter: verifier nonce, exact PCR allowlist/composite, quote signature, and pinned AK SPKI trust. |
| `tpm2-tools-swtpm-quote.fixture.json` | Public-interoperability fixture captured from the official `tpm2_quote` → `tpm2_checkquote` flow using `swtpm`; explicitly not physical-hardware evidence. |

```bash
node attestation/verify-cli.mjs demo packages/verify
```

Nothing here re-implements crypto or canonicalization: leaf preimage uses
`canonicalize()` and inclusion uses `verifyMerkleAnchor(..., { v2: true })` from
`@emilia-protocol/verify`, and the determinism guarantee comes from the repo's
existing reproducible packager.

## Strict TPM quote adapter

`tpm-quote-verifier.js` replaces the optional injected stub with an offline,
fail-closed verifier. The relying party must supply all trust inputs; the quote
cannot nominate its own nonce, AK trust root, PCR selection, or known-good PCR
values.

```js
import { verifyBuildAttestation } from './build-attestation.js';
import { verifyTpm2Quote } from './tpm-quote-verifier.js';

const result = verifyBuildAttestation(record, {
  rebuild,
  tpmHardwareVerifier: (quote) => verifyTpm2Quote(quote, {
    expectedNonce: challengeFromVerifier,
    trustedAkFingerprints: enrolledAkSpkiPins,
    expectedPcrSelection: { sha256: [0, 1, 2, 7] },
    expectedPcrValues: knownGoodPcrValues,
  }),
});
```

The adapter verifies a quote from an already-enrolled AK. It does not establish
that the AK lives in physical hardware or chains to a manufacturer EK
credential; that remains an enrollment/deployment ceremony. The checked-in
fixture was generated with a software TPM and exists only to prove byte-level
interoperability with the official `tpm2-tools` format.
