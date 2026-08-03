<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/scan` are documented here.

## 0.3.8 (2026-08-03)

### Added

- Add the owner-only, no-replace `EP-SCAN-ADOPTION-HANDOFF-v1` artifact, binding
  reviewed manifest and generated-scaffold digests to explicitly selected,
  receipt-required MCP actions and the bounded local refusal result without
  ambient identity, host data, credential values, or production-enforcement
  claims.

### Security

- Replace the loose read-word heuristic with an explicit precedence policy:
  state-change signals, write methods, and hybrid-operation ambiguity now
  outrank lexical read evidence, and only a leading read verb may pass through.
- Exercise exact `rotateApiKey` and `archiveCustomer` generated guards from a
  packed blank consumer and prove a missing receipt never reaches the handler.
- Redact short credential values for camelCase secret flags such as
  `--clientSecret`, `--accessToken`, `--refreshToken`, and `--authToken` in both
  split and `=` argument forms.

### Fixed

- Derive authority-report versions from the package version instead of the
  stale hard-coded `0.3.2` value.
- Pin generated MCP integration instructions to the audited exact
  `@emilia-protocol/mcp-guard@0.4.5` release.
- Reject missing or flag-shaped values for every value-bearing Scan option
  before scanning or writing.
- Publish exit code `64` consistently for authority CLI usage, argument, or filesystem errors.

### Tests

- Add behavioral CLI, authority-signal, package-version, hostile-classifier,
  rendered-report redaction, and packed-consumer coverage for the release paths.
