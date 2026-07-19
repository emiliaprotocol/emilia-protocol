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
| `reproducible-rebuild.mjs` | The live rebuild link, wrapping `scripts/verify-reproducible-package.mjs`. |
| `verify-cli.mjs` | `emit` / `verify` / `demo` CLI. |
| `build-attestation.test.js` | 25 vitest cases: happy path, multi-leaf inclusion, every fail-closed path, TPM boundary. |

```bash
node attestation/verify-cli.mjs demo packages/verify
```

Nothing here re-implements crypto or canonicalization: leaf preimage uses
`canonicalize()` and inclusion uses `verifyMerkleAnchor(..., { v2: true })` from
`@emilia-protocol/verify`, and the determinism guarantee comes from the repo's
existing reproducible packager.
