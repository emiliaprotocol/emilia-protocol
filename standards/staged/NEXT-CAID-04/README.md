# CAID revision 04 working packet

This directory stages `draft-schrock-canonical-action-identifier-04`. It is
not published. The last posted revision is -03, whose exact source is kept
in `../NEXT-CAID-03/`. This packet started from that source.

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
including the inputs it newly refuses.

## Files

- `UPLOAD-THIS/draft-schrock-canonical-action-identifier-04.xml`: the
  source.
- `RENDERS/`: the TXT and HTML renderings of that source.
- `SHA256SUMS.txt`: pins the source and both renderings.
- `CHANGES-VECTORS.json`: maps every "Changes since -03" item that changes
  processing or the reference registry (anchor `chg-...`) to the
  conformance vectors that pin it. Items anchored `ed-...` change text
  only.
- `VALIDATION.md`: the checks run and their results.

## What the draft restates, and what checks it

`node scripts/check-caid-04.mjs` fails unless all of these hold:

- Appendix A equals `caid/spec/caid.abnf` byte for byte.
- Appendix B (core and mapping reasons), the verification detail table, the
  limits table, and the IANA initial-contents tables equal the tables the
  script generates from `caid/spec/core.json`, `caid/registry/suites.json`,
  and the compiled code formats.
- Appendix D lists every type of registry version 5 with its
  `definition_sha256` from `digests.json`, in two listings: D.1, the 54
  initial IANA entries (45 active, 9 deprecated), and D.2, the 8 entries
  not requested of IANA. The script's `IANA_EXCLUDED` constant is the D.2
  list, with the reason for each entry. Section 12.2 and both subsections
  state those counts, and Section 14.4 states the counts of the whole
  registry.
- `node scripts/check-caid-04.mjs --emit` prints the tables, the two
  Appendix D listings with their counts, and the C.1 cbor-sha256 example
  for editing.
- Every value in Appendix C (the C.1 cbor-sha256 encoding, digest and CAID
  included), the Section 3.3 identifier example, the Section 4.2 type
  definition example, and the tool.call.1 example recompute, through
  `caid/spec/reference.mjs`, through hashing done in the script, and
  through its deterministic CBOR encoder.
- Every `chg-` item maps to vector ids that exist in the corpora.
- The normative and informative references, the [CAID-REGISTRY] commit and
  raw file URL, registry version 5 and its counts and file digest, the
  registries the Abstract and Section 12 name, the prose examples against
  the ABNF, BCP 14 markup, the removed -03 text, the wording each finding
  of the pre-filing review removes or requires, both renders, and the
  checksums.

## Hold

Submission is the author's decision. Before it:

1. The Implementation Status section points at `tree/main/caid`, which
   carries the -04 implementations only once this packet's pull request
   has merged. After `git fetch origin`, run
   `node scripts/check-caid-04.mjs --prefiling`: it also requires that
   origin/main carries registry version 5, `caid/spec/caid.abnf` and the
   -04 ports, and that the [CAID-REGISTRY] commit is reachable from
   origin/main.
2. [CAID-REGISTRY] is pinned to commit
   `708fd8fa9ca32ac7889834f234d3a1631e6bde93`, the last commit that
   changed `caid/registry/action-types.json`. If the merge rewrites that
   commit (a squash or rebase), re-pin both the blob and the raw file URL
   to the merged commit that carries the same file (SHA-256
   `1e30ddd3...2551a`) and re-render; the check requires the two URLs to
   name one commit.
3. Set the date, confirm each cited draft revision and that -03 is still
   the latest revision on Datatracker, re-render with the procedure in
   `VALIDATION.md`, and refresh `SHA256SUMS.txt` and `VALIDATION.md`.
4. The `caid` URI scheme is requested as Permanent through the draft's
   IANA section. An early review request to uri-review@ietf.org (RFC 7595,
   Section 7.1) is a separate author action.
