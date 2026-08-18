<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

- Add bounded `scan source` discovery for MCP, LangChain, Vercel AI SDK,
  Genkit, Python, and Java registrations with per-registration source evidence.
- Add tightening-only composition findings and `scan diff` against a reviewed,
  non-authorizing source baseline. Dynamic and duplicate registrations remain
  explicit review gaps; no command silently edits code or creates authority.

All notable changes to `@emilia-protocol/scan` are documented here.

## 0.4.0 (2026-08-17)

### Added

- Replace the refusal-only setup check with the deterministic four-case
  `EP-RR-1-LOCAL-v1` reproduction: missing receipt refusal, exact-action
  admission, action-substitution refusal, and one-use replay refusal.
- Emit the bounded RR-1 result and digest in
  `EP-SCAN-ADOPTION-HANDOFF-v2`, with synthetic-assurance and ephemeral-state
  limits stated in the artifact itself.

### Fixed

- Generate exact installs for the current audited
  `@emilia-protocol/mcp-guard@0.5.0` release.
- Bind every generated wrapper to the reviewed manifest's `action_type`,
  including unclassified mutators defaulted fail-closed, so an acquired receipt
  and the runtime guard cannot silently disagree about action identity.

## 0.3.9 (2026-08-05)

### Fixed

- Admit `retrieve`, `find`, `show`, `inspect`, and `browse` as leading read verbs.
  Common read-only tools (`retrieve_balance`, `findCustomerByEmail`, `showInvoice`)
  previously had no recognized read signal and were defaulted fail-closed, which
  reported plain reads as needing authorization and made real scan output harder to
  trust. Precedence is unchanged and was mutation-tested against the loosening:
  risk category, destructive annotation, state-change signals, write methods, and
  hybrid-operation markers all still outrank the read verb, so
  `retrieveAndDeleteCustomer`, `findAndRefundCharge`, and a `showRecord` carrying
  `destructiveHint` continue to require a receipt.

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
  split, `=`, slash, and command-string forms.
- Recognize ordinary inflections of state-changing verbs so descriptions such
  as `updates`, `archives`, and `rotates` cannot hide behind a read-shaped tool
  name.
- Bound regular-file reads before content ingestion; refuse non-regular files,
  symlinked path components, and files that change during the read.
- Install protection scaffolds from a private sibling staging directory as one
  directory operation, preventing output-path swaps from redirecting writes.

### Fixed

- Derive authority-report versions from the package version instead of the
  stale hard-coded `0.3.2` value.
- Pin generated MCP integration instructions to the audited exact
  `@emilia-protocol/mcp-guard@0.4.5` release.
- Reject missing or flag-shaped values for every value-bearing Scan option
  before scanning or writing.
- Publish exit code `64` consistently for authority CLI usage, argument, or filesystem errors.
- Reject unknown and duplicate CLI options instead of silently degrading a
  requested apply operation into a successful dry run.

### Tests

- Add behavioral CLI, authority-signal, package-version, hostile-classifier,
  rendered-report redaction, and packed-consumer coverage for the release paths.
