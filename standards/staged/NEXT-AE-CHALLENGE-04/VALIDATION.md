# Validation record

Validated on 2026-08-09 from the isolated -04 candidate packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings.
- `idnits 3.1.0 -m submission` passed with no nit reported.
- The rendered front matter states 9 August 2026 and an expiry of
  10 February 2027.
- A fresh `xml2rfc 3.34.0` rebuild produced TXT and HTML byte-identical to the
  retained renderings.
- `node scripts/check-ae-challenge-04.mjs` passed the focused source, render,
  revision-boundary, checksum, and immutable-posted-03 assertions.
- The source, TXT, and HTML bytes are pinned in `SHA256SUMS.txt`.

This candidate changes specification text and packet checks only. It does not
claim a corresponding runtime implementation, independent implementation, or
interoperability result for the new -04 behavior.
