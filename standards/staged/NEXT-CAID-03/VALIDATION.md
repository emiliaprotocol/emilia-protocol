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

When these checks ran, Datatracker had not yet published this packet; the
publication check below records the later posting.

## Publication check

Checked on 2026-09-26 after posting:

- The Datatracker submission API lists submission 169526 for
  `draft-schrock-canonical-action-identifier` revision 03 in state `posted`,
  and the document record shows revision 03 at 2026-09-26T16:30:22Z. No later
  revision exists.
- The IETF archive XML has SHA-256
  `867cad1093063b9a54ecc1de99443248069f2dfb51c05dc4a12073202ba25040` and the
  archive text has SHA-256
  `065e62f8de5054030e563c6a6c5427ad573aa0d9c8810380c2581157925a6a67`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. The archive rendered it
  with xml2rfc 3.34.1 and its delivery path injects request-specific Cloudflare
  markup, so the retained render stays the checksum-pinned local form. The
  posted HTML is that render; it already had no trailing whitespace, so it is
  byte-identical to the retained render.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.

Later normative changes are staged in `../NEXT-CAID-04/`.
