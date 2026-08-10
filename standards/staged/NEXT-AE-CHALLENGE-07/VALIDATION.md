# Validation record

Private candidate only. Not published or pushed.

The prior validation below is superseded. The current repaired XML SHA-256 is
`2fd28bb29bbe7aaa1b9a91b7216c72b10f19ac1224febdb473413cc06d8afa89`.
It is not a publication-ready validation record.

- `xmllint --noout`: PASS.
- `xml2rfc --text` and `--html`: PASS. The renderer reports four long
  source-code lines because the examples carry complete SHA-256 values.
- `idnits -m submission`: PASS with one warning covering those same four
  complete SHA-256 example lines. It reports no structural, reference,
  submission, filename, or date error.
- `node scripts/check-ae-challenge-07.mjs`: PASS, including immutable -06,
  current normative text, runtime fail-closed guards, v3 migration, finite-
  model source/result binding, renders, and packet checksums.
- Focused challenge suite after the first runtime repairs: PASS, 58 of 58 tests across
  `evidence-challenge.test.ts`, `evidence-challenge-durable.test.ts`, and
  `evidence-challenge-07-redteam.test.ts`.
- Model-to-Matter integration after the 128-bit nonce repair: PASS, 33 of 33
  tests.
- `node formal/check-evidence-challenge-claim-capacity.mjs`: PASS over 113
  finite same-team scenarios with explicit mutation counterexamples. This is
  scenario evidence, not exhaustive formal verification or a database-
  isolation refinement.
- `TLA2TOOLS_JAR=<checksum-verified v1.7.4 jar> npm run
  check:formal-traces`: PASS, 78 scenarios, 51 paired negative controls, and
  21 claims. The jar matched repository-pinned SHA-256
  `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Gate package: PASS, 326 passed, 0 failed, and 12 environment-gated skips.
- `npm run typecheck:lib`: PASS.
- Standalone runtime generation/check: PASS, 574 generated targets
  synchronized.
- Protocol and write discipline: PASS with 15 pre-existing route-size
  warnings and no critical finding.
- Executable security case from committed private bytes: PASS, 35 executable
  claims and 262 hashed evidence files, including release-byte
  reproducibility.
- Full repository suite: PASS, 8,774 passed, 103 explicitly environment-gated
  skips, and 0 failed across 534 test files.
- Independent protocol and runtime re-audit found four High protocol gaps and
  seven High runtime/evidence gaps. The protocol gaps and two immediate runtime
  defects are repaired in the current private bytes. Compound finalization,
  authoritative time, capability contract testing, and overclaimed finite-model
  obligations remain publication blockers.

The previously recorded full-suite and security-case results predate the current
repairs and MUST be rerun before they are cited. Not run or claimed in this
record: production `next build`, remote CI,
external interoperability, or independent implementation.

Revision -07 does not claim that a current reference backend implements the
normative compound claim-and-capacity transition. Production evaluation fails
closed unless the injected owner store supplies that method. Publication
remains blocked pending implementation or independent review of the exact
transition and a deliberate filing decision.
