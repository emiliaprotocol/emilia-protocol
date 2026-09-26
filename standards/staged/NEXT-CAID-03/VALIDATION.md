# Validation record

Validated on 2026-09-26 from the isolated CAID -03 working packet, after the
review revision of the enum-form, own-member, and unpaired-surrogate text.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT rendering and, with `--no-external-js`,
  the HTML rendering. The generated HTML's non-semantic trailing spaces were
  normalized before checksums were recorded. Re-rendering the previous staged
  XML with the same procedure reproduced its checked-in TXT and HTML byte for
  byte (apart from the HTML's self-referencing source file name).
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering.
- The source intentionally omits `submissionType` because this remains an
  individual draft with no adopted document stream. `xml2rfc` uses its IETF
  rendering default and emits an informational warning. It also renders the
  Standards Track category with the required consensus default.
- `npm run caid:conformance` passed the registry identity and enum-coverage
  checks, the Go unit tests, and all 73 core, 23 mapping, and 100
  consequential-action vectors in JavaScript, Python, and Go.
- The core corpus (version 2) includes positive USD and XAD cases plus
  fail-closed `NOT-A-CURRENCY`, bare-reference, unresolved-reference,
  digest-mismatch, and inline-enum cases, and the review additions: null enum
  members, U+0020-only inline trimming, embedded external values,
  own-member presence, and unpaired-surrogate refusals.
- `node scripts/check-caid-03.mjs` passed against these files.
- Re-run the same day after the Python port's whole-string grammar fix and
  the integer-field alignment: `npm run caid:conformance` passed all 88 core
  (corpus version 3), 25 mapping, and 100 consequential-action vectors in
  JavaScript, Python, and Go, and `node scripts/check-caid-03.mjs` passed.
  The draft text did not change; no grammar it states admits a trailing line
  feed.

Datatracker has not published this packet. Author review and submission are
still required; the published -02 archive remains authoritative until then.
