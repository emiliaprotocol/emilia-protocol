# Validation record

Validated on 2026-09-26. The source starts from the previously staged -04
(which carried the amount-string ABNF and the suite and unused-bit parsing
changes over -03) and keeps both changes.

## Rendering

- `xmllint --noout` passes for the source.
- `xml2rfc 3.34.0` renders the TXT (`--text`) and, with `--no-external-js`,
  the HTML (`--html`). Trailing spaces and tabs in the generated HTML are
  removed with `perl -pe 's/[ \t]+$//'` before checksums are recorded. The
  same procedure applied to the previously staged -04 source reproduces
  its checked-in TXT and HTML byte for byte, and applied to this source it
  reproduces the renders in `RENDERS/` byte for byte.
- `xml2rfc` reports two informational warnings and nothing else: the
  source omits `submissionType`, as -03 does, because this is an individual
  draft with no adopted document stream, so `xml2rfc` uses its IETF default
  and sets `consensus="true"` for a Standards Track document.
- Every sourcecode line is at most 69 columns. Long example lines are folded
  as specified in RFC 8792 (single backslash strategy), and
  `check-caid-04` unfolds them before recomputing.
- `idnits 3.1.0 -m submission` reports `PASS - No nit found` for the TXT
  rendering (74 pages).

## check-caid-04

`node scripts/check-caid-04.mjs` passes every check except one: 87 of the
vector ids in `CHANGES-VECTORS.json` are not yet in the corpora, because
corpus version 5 has not landed. It passes in full when the corpora carry
those ids (checked by pointing the map at a corpus that lists them).

Checks that pass on this tree:

- Appendix A equals `caid/spec/caid.abnf` byte for byte (155 lines), and
  every non-empty ABNF line appears in the TXT render. No other ABNF block
  remains in the body.
- Appendix B (16 core and 18 mapping reasons), the verification detail
  table, the limits table, and the IANA tables for suites, field types, code
  formats, transforms, and loss policies equal the tables generated from
  `caid/spec/core.json`, `caid/registry/suites.json`, and the compiled code
  formats.
- Appendix C recomputes under registry version 5 with its enum snapshots:
  the payment.release.1 object gives 230 canonical octets, digest
  `sha256:9622c6f6...3b56`, the CAID ending `...arxrO1Y`, and
  `definition_sha256` `sha256:3a5ad4c0...ff12`; the refusal list and its
  order; the verification result with its five details; the tool.call.1
  validation projection and its digest; the prior.auth.approve.2 code-field
  result and its `invalid_code` refusal; and the mapping example's profile
  digest, source digest, projected object, and CAID. Each is checked
  against `caid/spec/reference.mjs` and, where it is a hash, by hashing in
  the script. The mapping projection is rebuilt from the profile rules in
  the script itself.
- The Section 3.3 identifier is the Appendix C.1 CAID; the tool.call.1
  example reproduces
  `caid:1:tool.call.1:jcs-sha256:FdawgFwgN5tAtiZa-SCkVDrV3dS9w1yeXVQaDaZLQQQ`.
- The prose examples match or fail the ABNF as the text says (amount
  strings, timestamps, `G47.33` and `G4733`, nested reasons), the 16 final
  digest characters equal `b64url-z2`, and every registered suite matches
  the suite rule.
- Registry version 5 has 62 types, 53 active and 9 deprecated, and the
  draft cites the SHA-256 of `action-types.json` that `digests.json`
  records. The history v4 pin is `73a31f4a...2d26`. Only two v4 types
  changed validation projection in v5: `dns.record.delete.1` and
  `vendor.onboard.1`, both first pins.
- The normative references include RFC 8259, 3629, 7405, 7493, and 3986;
  the informative ones include RFC 7595, 7942, 8126, and 8792; every listed
  RFC is cited.
- The removed -03 text is gone outside the change logs ("No other
  normative text changes", accept-unregistered, the public-values
  sentence, "pending adoption", the narrow correction rule, the orphan
  identifier example, "requests no immediate IANA actions").
- No en or em dash appears in the source or the TXT render, the source is
  printable ASCII, and `SHA256SUMS.txt` matches.

Separate mutations of the source each make the check fail: one byte of
Appendix A, one hex digit of the C.1 digest, one parameter in the reason
table, a removed change anchor, the -03 "No other normative text changes"
sentence, swapped reasons in C.2, a changed detail rule in C.3, a changed
amount in the C.6 projection, a removed RFC 7493 reference, and an em
dash.

## Claims checked outside the script

- The preimage statement in Privacy Considerations: enumerating
  `amount_usd` from 1 through the reference validator finds 4000 after
  4000 candidates for the tool.call.1 example CAID.
- The code-format statement in Security Considerations: the pattern
  `(a|a){1,99}` took 31.5, 9.2, 34.4, and 137.7 ms in V8 on "a" repeated
  18, 20, 22, and 24 times and followed by "!", roughly quadrupling every
  two characters.
- RFC 7493 Section 2.1 excludes surrogates and noncharacters from member
  names and string values; Section 2.3 refuses duplicate names after
  unescaping.
- `caid` is absent from the IANA URI Schemes registry
  (`uri-schemes-1.csv`, 438 entries, fetched on 2026-09-26).
- `node scripts/check-caid-03.mjs` still passes for the posted -03 packet.

Datatracker has not published this packet. Submission is held; see
`README.md`.
