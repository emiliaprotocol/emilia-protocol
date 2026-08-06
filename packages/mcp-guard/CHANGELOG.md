<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/mcp-guard` are documented here.

## Unreleased

### Security

- Keep the exact bound execution arguments private from consent, signoff,
  issuer, annotation, and receipt-client callbacks. Each callback receives a
  detached copy and cannot rewrite the object later passed to the tool handler.

## 0.5.0 (2026-08-05)

### Added

- Add a bounded, exact-call MCP loop breaker that returns a truthful local 429
  after the configured identical-call budget, without network or payload mutation.

### Security

- Reuse the shared executor-action binder so MCP, LangChain, CrewAI, and OpenAI
  adapters derive exact call identity from the same canonical contract.

## 0.4.4 (2026-08-02)

### Fixed

- Restore the published package's blank-consumer ESM import by shipping the
  generated runtime companions referenced by the package entry point.
- Exercise the packed package from an empty consumer during the repository
  export gate so a workspace fallback cannot mask a broken npm artifact.

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
