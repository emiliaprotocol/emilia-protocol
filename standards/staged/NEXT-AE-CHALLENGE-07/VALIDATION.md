# Validation record

Private candidate only. Not published, uploaded, or represented as live.

The frozen XML SHA-256 is
`f3bde597934607a50c90facdcb9734355465cb8cfb18e563d5eaa10bdab54cee`.

- `xmllint --noout`: PASS.
- `xml2rfc --text` and `--html`: PASS. The renderer reports four long
  source-code lines because the examples carry complete SHA-256 values.
- `idnits -m submission`: PASS with one warning covering those same four
  complete SHA-256 example lines. It reports no structural, reference,
  submission, filename, or date error.
- `node scripts/check-ae-challenge-07.mjs`: PASS, including immutable -06,
  current normative text, runtime fail-closed guards, v3 migration, finite-
  model source/result binding, renders, and packet checksums.
- Focused AE-CHALLENGE and Model-to-Matter security suite: PASS, 111 of 111
  tests across seven files. This includes owner issuance, duplicate claim,
  capacity refusal without nonce burn, authoritative expiry, exact follow-up
  binding, fenced recovery, PostgreSQL transaction behavior, action swap,
  replay, and acknowledgement-loss cases.
- `node formal/check-evidence-challenge-claim-capacity.mjs`: PASS over 113
  finite same-team scenarios with explicit mutation counterexamples. This is
  scenario evidence, not exhaustive formal verification or a database-
  isolation refinement.
- `TLA2TOOLS_JAR=<checksum-verified v1.7.4 jar> npm run
  check:formal-traces`: PASS, 78 scenarios, 51 paired negative controls, and
  21 claims. The jar matched repository-pinned SHA-256
  `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Gate package: PASS, 326 passed, 0 failed, and 12 environment-gated skips.
- Full repository typecheck: PASS, including core, lib, rest, app, secure app,
  declarations, and TypeScript SDK.
- Standalone runtime generation/check: PASS, 574 generated targets
  synchronized.
- Packed-package export check: PASS, 12 packages, 166 imports, 2 assets, and
  165 typed entries, including `@emilia-protocol/gate/challenge-store-postgres`.
- Protocol and write discipline: PASS with 15 pre-existing route-size
  warnings and no critical finding.
- Executable security case from clean committed private bytes: PASS, 35 executable
  claims and 265 hashed evidence files, including release-byte
  reproducibility.
- Full repository Vitest suite from a clean checkout: PASS with 0 failures;
  11 files and 103 tests were explicitly environment-gated. The clean run
  includes release-byte reproducibility.

The earlier High runtime findings covering compound finalization,
authoritative owner time, callback impersonation, stale-worker recovery, and
overclaimed claim-and-capacity evidence are repaired in these bytes. The
remaining limits are stated in `HOSTILE-REVIEW.md` and are not presented as
implemented or independently verified.

Not run or claimed in this record: production `next build`, remote CI, live
PostgreSQL isolation or privilege testing, external interoperability, or an
independent implementation. The candidate is locally publication-formatted
and technically reviewable. Filing remains an explicit user decision.
