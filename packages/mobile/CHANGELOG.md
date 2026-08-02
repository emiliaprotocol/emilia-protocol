<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/mobile` are documented here.

## 0.2.3 (2026-08-01)

### Security

- Reject malformed or oversized iOS enrollment attestation tokens before CBOR
  inspection, matching the bounded package enrollment path.

## 0.2.2 (2026-08-01)

### Release

- Supersedes the unpublished `0.2.1` tag on the final protected-main release
  baseline. Package behavior is unchanged.

## 0.2.1 (2026-08-01)

### Security

- Harden signed mobile and enrollment JSON canonicalization against cycles,
  sparse arrays, accessors, symbol members, non-plain objects, malformed UTF-16,
  resource exhaustion, and values outside the closed protocol domain.
- Resolve verifier behavior through the declared
  `@emilia-protocol/verify` dependency rather than a repository-relative path,
  preserving runtime behavior in a blank installed consumer.
