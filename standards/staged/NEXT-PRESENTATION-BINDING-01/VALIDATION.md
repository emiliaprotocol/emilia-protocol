# Validation

- `xml2rfc 3.34.0 --no-network --text`: PASS.
- `xml2rfc 3.34.0 --no-network --html`: PASS.
- The retained text and HTML both contain Section 6.1, "Receipt and
  Presentation Evidence Remain Distinct."
- The title, abstract, composition, and residual-risk text limit the claim to
  binding submitted deterministic or attested display bytes to the signed
  action under relying-party-selected trust inputs. They do not claim proof of
  what the human perceived or what a malicious client displayed.
- xml2rfc retained the source draft's existing unused-RFC8785 warning. No new
  schema or reference warning was introduced by the boundary section.
- This is candidate rendering evidence, not submission or publication
  evidence.

## Publication check

Checked on 2026-09-27, when the posted snapshot was mirrored into
`standards/posted/`:

- The Datatracker submission API lists submission 168936 for
  `draft-schrock-ep-presentation-binding` revision 01 in state `posted`, and
  the document record shows revision 01 at 2026-09-12T15:06:51Z, the time of
  its "New version available" event. No later revision exists.
- The IETF archive XML has SHA-256
  `97d7a67ff8a70a6bea540e38810513ea01ca6f195a038f4c8235b3880cf67cb2` and the
  archive text has SHA-256
  `121fd0ba41c207fd6f683e2ae8a01acbbd7cb1e7fc889845620690eedadc2156`. Both
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
