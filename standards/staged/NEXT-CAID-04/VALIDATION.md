# Validation record

Validated on 2026-09-27. The source starts from the previously staged -04
(which carried the amount-string ABNF and the suite and unused-bit parsing
changes over -03) and keeps both changes.

## Rendering

- `xmllint --noout` passes for the source.
- `xml2rfc 3.34.0` renders the TXT (`--text`) and, with `--no-external-js`,
  the HTML (`--html`). Trailing spaces and tabs in the generated HTML are
  removed with `perl -pe 's/[ \t]+$//'` before checksums are recorded.
  Applied to the previously staged source, the same procedure reproduces
  its checked-in TXT and HTML byte for byte; applied to this source, it
  produces the renders in `RENDERS/`.
- `xml2rfc` reports two informational warnings and nothing else: the
  source omits `submissionType`, as -03 does, because this is an individual
  draft with no adopted document stream, so `xml2rfc` uses its IETF default
  and sets `consensus="true"` for a Standards Track document.
- Every sourcecode line is at most 69 columns. Long example lines are folded
  as specified in RFC 8792 (single backslash strategy), and
  `check-caid-04` unfolds them before recomputing. Appendix D is a listing,
  not a table, because a 64-digit digest does not fit a table row.
- `idnits 3.1.0 -m submission` reports `PASS - No nit found` for the TXT
  rendering (81 pages).
- `idnits 3.1.0` in its default mode reports one error,
  `DOWNREF_TO_LOWER_STATUS` for RFC 8785, which is an Informational RFC on
  the Independent Stream and not in the Downref Registry. Any IETF Last
  Call for this document must call out that downward reference, as BCP 97
  requires. Its warnings are the RFC 6234 downref, which the Downref
  Registry lists, a suggestion to cite BCP 14 by name, and table-of-contents
  indentation it misreads as appendix titles.

## check-caid-04

`node scripts/check-caid-04.mjs` passes every check on this tree:

- Appendix A equals `caid/spec/caid.abnf` byte for byte (160 lines), and
  every non-empty ABNF line appears in the TXT render. No other ABNF block
  remains in the body.
- Appendix B (16 core reasons, and 16 mapping reasons besides the two that
  computation and mapping stage A share), the verification detail table,
  the limits table (13 rows), and the IANA tables for suites, field types,
  code formats (with a syntax reference per format), transforms, and loss
  policies equal the tables generated from `caid/spec/core.json`,
  `caid/registry/suites.json`, and the compiled code formats. Appendix D
  equals the listing generated from `caid/registry/action-types.json` and
  `caid/registry/digests.json`.
- Appendix C recomputes under registry version 5 with its enum snapshots:
  the payment.release.1 object gives 230 canonical octets, digest
  `sha256:9622c6f6...3b56`, the CAID ending `...arxrO1Y`, and
  `definition_sha256` `sha256:3a5ad4c0...ff12`; the refusal list and its
  order; the verification result with its five details; the tool.call.1
  validation projection and its digest; the prior.auth.approve.2 code-field
  result and its `invalid_code` refusal; and the mapping example's profile
  digest, source digest, projected object, and CAID. Each is checked
  against `caid/spec/reference.mjs` and, where it is a hash, by hashing in
  the script.
- The Section 3.3 identifier is the Appendix C.1 CAID; the tool.call.1
  example reproduces
  `caid:1:tool.call.1:jcs-sha256:FdawgFwgN5tAtiZa-SCkVDrV3dS9w1yeXVQaDaZLQQQ`.
- All 40 `chg-` items of "Changes since -03" map to vector ids that exist
  in the core corpus v5, the mapping corpus v2, or the interoperability
  corpus (`CHANGES-VECTORS.json`).
- The prose examples match or fail the ABNF as the text says, the 16 final
  digest characters equal `b64url-z2`, and every registered suite matches
  the suite rule.
- Registry version 5 has 62 types, 53 active and 9 deprecated, and the
  draft cites the SHA-256 of `action-types.json` that `digests.json`
  records. The history v4 pin is `73a31f4a...2d26`.
- The normative references include RFC 8259, 3629, 7405, 7493, and 3986,
  IEEE 754, and the reference registry at a fixed commit; the informative
  ones include RFC 7595, 7942, 8126, and 8792 and the Unicode Standard;
  every listed reference is cited. The cited Internet-Draft revisions are
  the latest ones below.
- The removed -03 text is gone outside the change logs, no en or em dash
  appears in the source or the TXT render, the source is printable ASCII,
  and `SHA256SUMS.txt` matches.

## Claims checked outside the script

- The preimage statement in Privacy Considerations: enumerating
  `amount_usd` from 1 through the JavaScript implementation finds 4000
  after 4000 candidates for the tool.call.1 example CAID (26 ms).
- The code-format statement in Security Considerations: the pattern
  `(a|a){1,99}` took 31.5, 9.2, 34.4, and 137.7 ms in V8 on "a" repeated
  18, 20, 22, and 24 times and followed by "!", roughly quadrupling every
  two characters.
- The cost statement in Section 10.7, measured on a laptop (darwin/arm64,
  node 20.20.2, Python 3.11.15, Go 1.27.0) with `computeCaidJson` and its
  counterparts: a 33,554,367-octet array of 16 million zeros is refused in
  0.9 s and 561 MiB (JavaScript), 11.5 s and 982 MiB (Python), and 0.7 s
  and 1,221 MiB (Go); a 15 MiB array computes in 0.5 s and 314 MiB, 5.3 s
  and 772 MiB, and 0.3 s and 572 MiB.
- The document encoding limit: a definition whose validation projection
  holds a 134,217,728-character member is `invalid_definition`, and a
  mapping source holding one is `source_not_canonicalizable`, in
  JavaScript, Python, and Go.
- RFC 7493 Section 2.1 excludes surrogates and noncharacters from member
  names and string values; Section 2.3 refuses duplicate names after
  unescaping.
- `caid` is absent from the IANA URI Schemes registry
  (`uri-schemes-1.csv`, 435 rows, fetched on 2026-09-27).
- `draft-thallapelly-oasnt-caid-01` Section 6.4 states that identifiers
  from different profiles are never compared; its Acknowledgments credit
  the author's review with that observation, so Section 3.6 no longer
  calls it independent.
- `node scripts/check-caid-03.mjs` still passes for the posted -03 packet.
- The Datatracker API, queried on 2026-09-27, reports revision 03 of
  draft-schrock-canonical-action-identifier (posted
  2026-09-26T16:30:22Z) as the latest, and the IETF archive URL for -04
  returns 404, so -04 is the next revision. It reports
  draft-schrock-ep-authorization-receipts-13 (header date 11 September
  2026), draft-schrock-action-evidence-boundary-07 (25 September 2026),
  draft-schrock-ep-authorization-evidence-chain-06 (6 September 2026),
  and draft-thallapelly-oasnt-caid-01 as the latest revisions of the
  cited drafts; draft-morrow-sogomonian-exec-outcome-attest-00 expires on
  2026-10-06.

Datatracker has not published this packet. Submission is held; see
`README.md`.
