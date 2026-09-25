# Validation

Validated on 2026-09-24 with the repository-local candidate source.

- `xmllint --noout UPLOAD-THIS/draft-schrock-action-evidence-boundary-06.xml`:
  PASS.
- `xml2rfc 3.34.0 --text`: PASS; produced the retained text render.
- `xml2rfc 3.34.0 --html`: PASS; produced the retained HTML render.
- `idnits 3.1.0 -m submission RENDERS/draft-schrock-action-evidence-boundary-06.txt`:
  PASS with no nits.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for the XML, text, and HTML files.

The two xml2rfc render commands emit the inherited informational warning that
the source has no explicit `submissionType` and will use the IETF stream. No
schema, reference, or idnits failure was reported.

The WIMSE AIMS, AuthZEN Authorization API, COAZ, COAZ-MCP, and AP2 references
were checked against their primary publication pages on 2026-09-24. The AP2
reference is pinned to commit
`e1ea56db72a6385bce3e5c1112b3a56ce60acb43` rather than a moving branch.

These checks establish that the candidate parses, renders, and passes the
local submission-nits check. They are not evidence of IETF submission,
publication, working-group adoption, protocol-owner review, implementation
interoperability, or deployment.

## Publication check

Checked on 2026-09-24 after posting:

- The Datatracker submission API lists submission 169466 for
  `draft-schrock-action-evidence-boundary` revision 06 in state `posted`, and
  the document record shows revision 06 at 2026-09-25T02:15:03Z.
- The IETF archive XML has SHA-256
  `82eaf5eea816c037cb8dcb4608c8735a96f09850aad0a6df5bac021964bf17c5` and the
  archive text has SHA-256
  `988c8e50bd20bd8d1e55a486067bb20911cc841a699e26eaaa75ce3e4a067156`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. The archive rendered it
  with xml2rfc 3.34.1 and its delivery path injects request-specific Cloudflare
  markup, so the retained render stays the checksum-pinned local form.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.
