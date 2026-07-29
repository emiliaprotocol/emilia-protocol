<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

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
