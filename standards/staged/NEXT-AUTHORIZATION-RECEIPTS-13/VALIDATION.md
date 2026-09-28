# Validation

- `xml2rfc 3.34.0 --no-network --text`: PASS.
- `xml2rfc 3.34.0 --no-network --html`: PASS.
- The retained text and HTML both contain Section 13.13, "What Successful
  Verification Does Not Establish."
- xml2rfc retained the source draft's existing warnings: no explicit stream on
  an IETF Standards Track document and inferred `consensus="true"`. No new
  schema or reference warning was introduced by the boundary section.
- This is candidate rendering evidence, not submission or publication
  evidence.

## Publication check

Checked on 2026-09-27, when the posted snapshot was mirrored into
`standards/posted/`:

- The Datatracker submission API lists submission 168935 for
  `draft-schrock-ep-authorization-receipts` revision 13 in state `posted`, and
  the document record shows revision 13 at 2026-09-12T15:05:02Z, the time of
  its "New version available" event. No later revision exists.
- The IETF archive XML has SHA-256
  `77e7021e116bebbd8e786dd27b51468701ea4887dfa0dd8d692e919f1fd00ffb` and the
  archive text has SHA-256
  `74ae85d83e8c21c8a3b470b7444474f56cb93858bf848a6a14d1a2991f5116a6`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. The archive rendered it
  with xml2rfc 3.34.1, so its recorded versions and some CSS rules differ, and
  the retained render stays the checksum-pinned local form. Checked on
  2026-09-28, the posted HTML is the archive HTML with the per-request
  Cloudflare challenge script, which the archive delivery path appends before
  `</body>`, removed; two fetches differed only in that script and were
  byte-identical once it was removed.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.
