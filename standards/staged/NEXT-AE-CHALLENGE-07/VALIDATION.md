# Validation record

Candidate only. Not published.

Validated on 2026-08-10 against
`UPLOAD-THIS/draft-schrock-ae-challenge-07.xml`.

- `xmllint --noout`: PASS.
- `xml2rfc --text` and `--html`: PASS. The renderer reports four long
  source-code lines because a quoted `sha256:` value with 64 hexadecimal
  digits cannot fit within 72 columns; the values are intentionally complete
  rather than invalid placeholders.
- `idnits -m submission`: PASS except for the same four unavoidable full
  SHA-256 example lines; no structural, reference, submission, or date nit.
- `node scripts/check-ae-challenge-07.mjs`: PASS, including immutable -06,
  normative-text, runtime-ordering, v2 migration, render, and checksum guards.
- `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts`: PASS, 45 of 45 tests.
- `node formal/check-evidence-challenge-lifecycle.mjs`: PASS over 1,024
  configurations plus restart, ordering, and concurrency checks, including the
  new ActionMismatchIsInert obligation and mutation.
- `node formal/check-evidence-challenge-claim-capacity.mjs`: PASS over 18
  selected states and edges, with counterexamples for expiry-before-retained-
  replay, split
  capacity-before-claim, claim-before-capacity, independent global-cap shards,
  and stale-owner finalization without fencing.
- `TLA2TOOLS_JAR=<checksum-verified v1.7.4 jar> npm run
  sync:formal-traces`: PASS, 78 scenarios, 51 paired negative controls, and 21
  claims. The jar matched repository-pinned SHA-256
  `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Gate package: PASS, 326 passed, 0 failed, 12 environment-gated skips.
- Focused packet, protocol-discipline, write-discipline, public-claim,
  packed-export, formal-trace, and standalone-runtime gates: PASS.
- Full repository test, build, clean-checkout security-case, and generated
  proof-stat gates: pending the clean-commit reproducibility cycle.

Revision -07 does not claim the reference implementation supplies the compound
capacity transition, configurable cap buckets, self-describing issuance, or
fenced reservation recovery.
