<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/scan` are documented here.

## 0.3.8 (2026-08-03)

### Security

- Replace the loose read-word heuristic with an explicit precedence policy:
  state-change signals, write methods, and hybrid-operation ambiguity now
  outrank lexical read evidence, and only a leading read verb may pass through.
- Exercise exact `rotateApiKey` and `archiveCustomer` generated guards from a
  packed blank consumer and prove a missing receipt never reaches the handler.

### Fixed

- Derive authority-report versions from the package version instead of the
  stale hard-coded `0.3.2` value.
- Pin generated MCP integration instructions to the audited exact
  `@emilia-protocol/mcp-guard@0.4.5` release.

### Tests

- Add behavioral CLI, authority-signal, package-version, hostile-classifier,
  and packed-consumer coverage for the release paths.
