<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## 2.8.5 (2026-09-05)

- Pin wheel and source-distribution metadata to version 2.4, which the pinned
  release checker supports. The 2.8.4 release failed this check before upload.
- Carry the 2.8.4 security fixes unchanged under a fresh immutable release tag.

## 2.8.4 (2026-09-05)

### Security

- Refuse malformed nested payload, signature, and anchor fields through a
  structured verification result. Unencodable Merkle-proof hash text now fails
  verification instead of raising an exception.

### Changed

- Publish the corrected installation guidance with the current reproducible
  Python release toolchain.
- Set the supported Python floor to 3.10 so runtime metadata and the pinned
  build toolchain describe the same supported interpreter line.
- Parse the full one-through-nine-digit RFC 3339 fractional-second profile on
  Python 3.10 instead of relying on interpreter-version-specific
  `datetime.fromisoformat` behavior.

## 2.8.3 (2026-08-01)

### Security

- Enforce the closed provenance action-scope grammar, reject the malformed
  empty-prefix wildcard `.*`, and require a universal child scope to be funded
  by a universal parent scope, matching the TypeScript verifier.

## 2.8.2 (2026-07-29)

- Reissues the unreleased 2.8.1 verifier behavior from the exact protected-main
  commit after its immutable tag was created before the final release merge.
  No verifier API or acceptance behavior changes from 2.8.1.

## 2.8.1 (2026-07-29)

- Trust Receipt verification treats pinned `compromised_at` as terminal and
  supports an optional relying-party `now` for refusing future-issued receipts,
  matching the JavaScript and Go conformance behavior.

## 2.8.0 (2026-07-21)

### Added

- Same-team Python implementations and shared-vector coverage for authority
  document/proof joining and outcome binding.
- Ordered-prefix quorum conformance and stricter revocation statement grammar,
  key identity binding, and closed-member validation.

### Security

- Relying-party authority, action, executor, and revoker pins remain distinct
  from cryptographic validity; malformed or presenter-expanded artifacts fail
  closed.
