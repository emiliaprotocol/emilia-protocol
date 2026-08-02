<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/mcp-guard` are documented here.

## 0.4.3 (2026-08-01)

### Release

- Supersedes the unpublished `0.4.2` tag on the final protected-main release
  baseline. Package behavior is unchanged.

## 0.4.2 (2026-08-01)

### Added

- A durable, tenant-scoped PostgreSQL provenance-ledger store and packaged
  reference SQL with atomic compare-and-append semantics.

### Security

- Reuse the shared strict JSON canonicalizer so cycles, accessors, symbol
  members, sparse arrays, and non-JSON objects fail closed before digesting.
- Bound the per-process action-gate cache and retain one-time state in the
  shared consumption store, so unique hostile argument sets cannot grow memory
  without limit or erase replay protection through eviction.
- Keep ledger state private behind immutable snapshots, verify durable history
  on startup, and fail closed on malformed or conflicting storage results.
