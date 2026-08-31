<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## 0.3.0 (2026-08-30)

- Add opt-in hybrid Ed25519 plus ML-DSA-65 work attestations while preserving
  the existing EP-ATTEST-v2 signed bytes.
- Require the issuer and verifier releases that expose the hybrid receipt
  modules, preventing an installed consumer from resolving an older,
  incompatible issuer package.
