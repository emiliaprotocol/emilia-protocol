# Validation record

Validated on 2026-08-09 against
`UPLOAD-THIS/draft-schrock-ae-challenge-05.xml`.

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS. A clean rebuild in a fresh
  temporary directory was byte-identical to both retained renderings.
- `idnits 3.1.0 -m submission`: PASS, no nits found.
- `node scripts/check-ae-challenge-05.mjs`: PASS. The focused checker verifies
  OAuth non-substitution and revision-pinned citations, the non-critical retry
  rules, non-promissory timing language, bounded state-exhaustion behavior,
  authoritative replay-domain requirements, conformance cases, retained
  renderings, checksum manifest, and the immutable revision -04 source. The
  pinned revision -04 XML SHA-256 is
  `db58ddde429ca0da23cf50d8a16ece0f973d574d1e27d4cee6d7f6319069fbe3`.
- `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts`: PASS, 43 of 43 tests, including
  the new routing guard that keeps a native OAuth transaction grant primary and
  permits coexistence only under an explicit composition profile.
- `node formal/check-evidence-challenge-lifecycle.mjs`: PASS. The existing
  bounded model checked 1,024 sequential lifecycle states plus the listed
  restart and concurrency properties. It models the durable stateful issuance
  path; it does not model revision -05's optional self-describing issuance or
  new cap behavior.
- Authored source, checker, and packet Markdown pass Git's whitespace check.
  The retained HTML is the byte-for-byte `xml2rfc` output and contains the
  generator's own trailing whitespace.

The implementation-status appendix remains intentionally limited. The
same-team implementation exercises durable stateful issuance and atomic
consumption across workers and restarts. It does not yet implement the -05
configurable cap behavior or self-describing issuance, and no independent
implementation or interoperability claim is made.

The routing helper does not validate OAuth artifacts. It only prevents an
integration that has independently determined a native transaction grant is
required from selecting AE-CHALLENGE as a substitute.

`SHA256SUMS.txt` pins the upload XML and both retained renderings.
