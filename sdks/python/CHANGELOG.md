# Changelog

## 0.11.0 (2026-08-30)

- Changed the canonical import namespace from `ep` to `emilia_protocol` to
  avoid colliding with the unrelated PyPI `ep` distribution.
- Replaced the asynchronous `httpx` preview client with the synchronous,
  standard-library implementation and removed all runtime dependencies.
- Rebased the public surface to runtime-backed handshake, trust-gate, and v1
  receipt/signoff/evidence routes.
- Added one-time receipt consumption, post-mutation execution attestation, and
  the fail-closed `require_receipt` orchestration helper, including quorum
  signoff fan-out.
- Removed unsupported Eye, handshake-consume, legacy signoff, cloud-preview,
  delegation, commit, and batch methods.
- Added installed-wheel metadata, namespace, route-contract, and negative
  lifecycle tests.
- Set the supported Python floor to 3.10, matching the pinned build toolchain
  and avoiding an unsupported Python 3.9 release line.

This is a breaking release. Replace `from ep import ...` with
`from emilia_protocol import ...` and remove `await` from client calls.
