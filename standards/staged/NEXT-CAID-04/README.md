# CAID-04 publication provenance packet

Status: posted on 2026-09-28 as
`draft-schrock-canonical-action-identifier-04` through Datatracker submission
169585 (Datatracker time 2026-09-28T07:24:09Z, 97 pages). It is an active
individual Internet-Draft. It is not a working-group item, an RFC, or IETF
endorsement, and posting is not review by any referenced protocol owner.

The XML under `UPLOAD-THIS/` is the exact submitted -04 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot is
[`../../posted/draft-schrock-canonical-action-identifier-04.xml`](../../posted/draft-schrock-canonical-action-identifier-04.xml);
CAID-03 is retained in `../../archive/`. The publication check is recorded at
the end of `VALIDATION.md`.

-04 is a substantive revision. It makes the processing model complete and
machine-checkable: strict JSON text input, host values, one data model with
one limits table, definition conformance, `definition_sha256` and
resolution, code fields with named formats, the monotone enum advance, a
fixed reason order with verification details, normative mapping stages, a
rewritten Security section, a new Privacy section, seven IANA registries
(Appendix D.1 lists the initial action types; D.2 lists the reference
registry entries that are not requested of IANA) and the `caid` URI scheme,
and an Implementation Status section. The
draft's "Changes since -03" section lists every normative change,
including the inputs it newly refuses. The suites, the digest, and the
canonical form of every object that both -03 and -04 accept do not change;
some action objects whose CAIDs were valid under -03 are refused.

## Files

- `UPLOAD-THIS/draft-schrock-canonical-action-identifier-04.xml`: the
  submitted source.
- `RENDERS/`: the TXT and HTML renderings of that source.
- `SHA256SUMS.txt`: pins the source and both renderings.
- `CHANGES-VECTORS.json`: maps every "Changes since -03" item that changes
  what the operations of the draft's Section 1.2 accept, refuse, or
  report, or changes the reference registry (anchor `chg-...`), to the
  conformance vectors that pin it. Items anchored `ed-...` are not pinned
  by vectors: Section 14.5 lists requirements on parties those operations
  cannot observe (issuers, type authors, registrants, executors, carrying
  protocols, relying parties, deployments, applications), and Section 14.6
  lists changes to the text alone.
- `VALIDATION.md`: the checks run and their results.

## What the draft restates, and what checks it

`node scripts/check-caid-04.mjs` fails unless all of these hold:

- Appendix A equals `caid/spec/caid.abnf` byte for byte.
- Appendix B (core and mapping reasons), the verification detail table, the
  limits table, and the IANA initial-contents tables equal the tables the
  script generates from `caid/spec/core.json`, `caid/registry/suites.json`,
  and the compiled code formats.
- Appendix D lists every type of registry version 5 with its
  `definition_sha256` from `digests.json`, in two definition lists: D.1,
  the 54 initial IANA entries (45 active, 9 deprecated), and D.2, the 8
  entries not requested of IANA. The script's `IANA_EXCLUDED` constant is
  the D.2 list, with the reason for each entry. Section 12.2, both
  subsections and the `ed-iana` change item state those counts, and
  Section 14.4 states the counts of the whole registry. No page of the TXT
  separates an entry's name line from its digest line.
- `node scripts/check-caid-04.mjs --emit` prints the tables, the two
  Appendix D lists with their counts, and the C.1 cbor-sha256 example
  for editing.
- Every value in Appendix C (the C.1 cbor-sha256 encoding, digest and CAID
  included), the Section 3.3 identifier example, the Section 4.2 type
  definition example, and the tool.call.1 example recompute, through
  `caid/spec/reference.mjs`, through hashing done in the script, and
  through its deterministic CBOR encoder. Every digest field of the
  Appendix C objects is the SHA-256 of a short example string the script
  names, or recomputes from the C.6 source, as Section 11 says.
- Appendix D.2's entries are unchanged member for member from
  `history/action-types.v4.json`, which is the registry version 4 file
  that `digests.json` pins and that Section 14.4 names.
- Every `chg-` item maps to vector ids that exist in the corpora.
- The Section 4.7 registration is the registry version 5 entry for
  tool.call.1, member for member, so the draft gives one text for it.
- The normative and informative references, the raw file URL at a fixed
  commit that [CAID-REGISTRY] targets, registry version 5 and its counts
  and file digest, the registries the Abstract and Section 12 name, the
  prose examples against the ABNF, BCP 14 markup, the removed -03 text,
  the wording each finding of the pre-filing review and of both audits of
  its fixes removes or requires, the banned wording (claims of adoption or
  endorsement, of independent implementations, post-quantum and FIPS
  claims), both renders, table rows split across a page, the page count
  that `VALIDATION.md` states, and the checksums. No line of the TXT ends
  inside a closed-set value that contains a hyphen (a field type,
  transform, loss policy, code format, parameter kind, or suite). Tool names are not in the
  public script; grep the XML and TXT for them by hand, from outside the
  repository, before upload.
- Section 13's statement that no implementation implements cbor-sha256:
  the JavaScript, Python and Go core and grammar runners fail nothing and
  skip exactly the vectors that apply only to an implementation of it.
- When `xml2rfc 3.34.0` is on PATH, both renders equal a fresh render of
  the source (`--renders` requires it).
- The posted XML and TXT in `../../posted/` equal the packet byte for byte,
  and the posted HTML carries no Cloudflare challenge markup. All three have
  the SHA-256 values that `STATUS.json` records in
  `september_28_2026_caid_wave`.

## Filing record

Pull request #824 merged the final state of this packet, with the code and
corpus fixes its draft describes, into main as `2d8bde58c` at
2026-09-28T06:49:54Z. The Datatracker submission API records the upload at
2026-09-28T06:56:34Z and the posting at 2026-09-28T07:24:11Z. On 2026-09-28,
after posting, `node scripts/check-caid-04.mjs --prefiling` passed against
origin/main at `2d8bde58c`, which `git ls-remote` confirmed was the remote
main, including the comparison with a fresh `xml2rfc 3.34.0` render.
[CAID-REGISTRY] is pinned to commit
`cea10b85e96460a04bf55d683a1ebc34e8b2c9a6`, whose
`caid/registry/action-types.json` is registry version 5. The `caid` URI
scheme is requested as Permanent through the draft's IANA section; an early
review request to uri-review@ietf.org (RFC 7595, Section 7.1) is a separate
author action and is not recorded here.
