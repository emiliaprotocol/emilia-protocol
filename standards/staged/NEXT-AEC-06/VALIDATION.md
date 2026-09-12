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
