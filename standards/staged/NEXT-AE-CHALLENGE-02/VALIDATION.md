# Validation record

Validated on 2026-08-07 from the isolated AE Challenge -02 working packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings without a warning.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering.
- The rendered front matter identifies revision -02, intended status
  Informational, date 7 August 2026, and expiry 8 February 2027.
- The rendered IANA section contains the complete RFC 6838 registration
  template, requests the standards-tree subtype, assigns change control to the
  IETF, and says the registration is not provisional.
- The only substantive source delta from -01 is publication-path and IANA
  process text. The challenge object, lifecycle, refusal behavior, security
  boundary, and implementation-status claims are unchanged.
- `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts` passed 40 tests in 2 files.
- `npm run check:standalone-runtimes` reported all 557 generated standalone
  runtimes synchronized.
- A fresh `xml2rfc 3.34.0` rebuild from `UPLOAD-THIS/`, followed by normalization
  of non-semantic trailing spaces in the generated HTML, produced TXT and HTML
  byte-identical to the staged renderings. `shasum -a 256 -c SHA256SUMS.txt`
  verified all three pinned files.

Datatracker published revision -02 on 2026-08-07 as an Informational individual
draft identifying the Independent Stream. The immutable IETF archive XML is
byte-identical to `UPLOAD-THIS/`, and the archive TXT is byte-identical to the
staged TXT rendering. The local HTML rendering is retained because the live
archive response is modified by CDN-injected script and generator-environment
comments. The checklist-complete note in `ISE-SUBMISSION.md` is staged in Gmail
and remains unsent. IANA processing is expected at IETF conflict review if the
Independent Stream submission advances.
