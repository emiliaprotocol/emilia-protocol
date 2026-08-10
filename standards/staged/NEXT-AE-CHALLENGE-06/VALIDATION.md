# Validation record

Published on the IETF Datatracker on 2026-08-10. The retained XML and TXT are
byte-for-byte identical to the immutable IETF archive artifacts.

Validated on 2026-08-10 against
`UPLOAD-THIS/draft-schrock-ae-challenge-06.xml`.

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS.
- `idnits 3.1.0 -m submission`: PASS, no nits found.
- `node scripts/check-ae-challenge-06.mjs`: validates the cap-first ordering,
  binding capacity reservation, no-policy-oracle response, authoritative owner
  replay classification, HTTP 503 mapping, retained renderings, checksums, and
  immutable published -05 source.
- `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts`: PASS, 44 of 44 tests.
- `node formal/check-evidence-challenge-lifecycle.mjs`: PASS, including 1,024
  sequential lifecycle states and the listed restart and concurrency checks.
  That existing model does not establish the new -06 capacity-reservation or
  replay-shard routing requirements.
- `npm run test:run`: PASS, 8,865 tests across 533 files (8,762 passed and 103
  platform-specific skips).
- `npm run build`: PASS. The existing unused-eslint-disable warnings remain
  warnings and are unrelated to this packet.
- `TLA2TOOLS_JAR=<checksum-verified v1.7.4 jar> npm run
  check:security-case`: PASS, 35 executable claims over 259 hashed evidence
  files. The jar matched the repository-pinned SHA-256
  `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Revision -06 does not claim that the reference implementation already
  supplies the new configurable capacity-reservation or replay-shard routing
  interfaces.
- `SHA256SUMS.txt` pins the upload XML and both retained renderings.

The immutable published -05 XML SHA-256 is
`77fce83124c69fbd1cd5b45fb13aba64d00a2ffdd4f17c4610f6ace895a8106b`.
