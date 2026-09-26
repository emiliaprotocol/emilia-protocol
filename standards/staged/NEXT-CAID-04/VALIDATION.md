# Validation record

Validated on 2026-09-26, starting from the published -03 source.

- The starting XML is `../NEXT-CAID-03/UPLOAD-THIS/`, byte-identical to the
  IETF archive copy of -03.
- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT rendering and, with `--no-external-js`,
  the HTML rendering. The generated HTML's non-semantic trailing spaces were
  normalized before checksums were recorded. The same procedure applied to
  the unchanged -03 source reproduced its checked-in TXT and HTML byte for
  byte.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the TXT
  rendering.
- The source omits `submissionType`, as -03 does, because this remains an
  individual draft with no adopted document stream. `xml2rfc` uses its IETF
  rendering default and emits an informational warning.
- The ABNF accepts exactly the strings that the JavaScript and Go amount
  regexes accept, over all 111,111 strings of up to five characters drawn
  from digits 0, 1, and 9, "-", ".", "+", "e", space, line feed, and comma.
  On this base the Python port differs on 171 of those strings, each ending
  in a line feed, because `re.match` with `$` accepts a final line feed. The
  open Python whole-string fix (#811) removes all 171 differences.
- `node scripts/check-caid-04.mjs` passed. It checks the ABNF in the source,
  the TXT rendering, and `caid/DESIGN.md`, and compares the JavaScript
  reference with a matcher written from the ABNF over the draft's examples
  and all 7,381 strings of up to four characters from a nine-character
  alphabet. Separate mutations of the reference that admit a leading zero,
  a final line feed, or a leading "+", or that report a non-matching string
  as `mistyped_field`, each make the check fail.
- `node scripts/check-caid-03.mjs` still passes for the published -03 packet.
- `npm run caid:conformance` passed the registry identity and enum-coverage
  checks, the Go unit tests, and all 73 core, 23 mapping, and 100
  consequential-action vectors in JavaScript, Python, and Go. This packet
  changes no corpus.

Datatracker has not published this packet. It is held until it carries
further substance; see `README.md`.
