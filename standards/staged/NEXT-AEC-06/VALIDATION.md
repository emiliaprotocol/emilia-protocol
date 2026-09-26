# AEC -06 validation

6 September 2026.

- xml2rfc: XML accepted and TXT/HTML rendered.
- idnits 3.1.0: no formatting nits; three `POSSIBLE_DOWNREF` findings for the
  normative CAID, Quorum, and Authorization Receipts Internet-Drafts. These
  dependencies remain normative because their rules are required by the
  selected profiles. The findings are retained, not counted as a clean pass.
- SHA256SUMS.txt identifies the exact XML and render bytes.

The implementation-status section distinguishes structured evaluation from the
legacy string API, and same-team tests from independent interoperability.
Final integrated code results are recorded separately; this packet is not a
package release, deployment, submission, or acceptance receipt.

## Publication check

Checked on 2026-09-26, when the posted snapshot was mirrored into
`standards/posted/`:

- The Datatracker submission API lists submission 168689 for
  `draft-schrock-ep-authorization-evidence-chain` revision 06 in state
  `posted`, and the document record shows revision 06 at
  2026-09-06T17:33:02Z, the time of its "New version available" event. No
  later revision exists.
- The IETF archive XML has SHA-256
  `69fef7053014c053e274f6396afdc9ea77943b6538876c8e49707d51796c1585` and the
  archive text has SHA-256
  `cb7ef78f9bb5f847e0e4eb5038f5f1a82db0f35143ece8e9ad881522bf35024c`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. Both record xml2rfc
  3.34.0; the archive copy lists different Python and library versions, and
  its delivery path injects request-specific Cloudflare markup, so the
  retained render stays the checksum-pinned local form. The posted HTML is
  that render with trailing whitespace removed.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.
