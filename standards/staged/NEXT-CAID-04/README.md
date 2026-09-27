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
(with the initial action types listed in Appendix D) and a provisional
`caid` URI scheme, and an Implementation Status section. The
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
  and the compiled code formats, and Appendix D equals the listing it
  generates from the registry and `digests.json`.
  `node scripts/check-caid-04.mjs --emit` prints them for editing.
- Every value in Appendix C, the Section 3.3 identifier example, and the
  tool.call.1 example recompute, through `caid/spec/reference.mjs` and
  through hashing done in the script.
- Every `chg-` item maps to vector ids that exist in the corpora.
- The normative references, registry version 5 and its counts and file
  digest, the prose examples against the ABNF, the removed -03 text, both
  renders, and the checksums.

## Hold

Submission is the author's decision. Before it:

1. The Implementation Status section points at `tree/main/caid`, which
   carries the -04 implementations only once this packet's pull request
   merges. Merge first.
2. [CAID-REGISTRY] is pinned to commit
   `708fd8fa9ca32ac7889834f234d3a1631e6bde93`, the last commit that
   changed `caid/registry/action-types.json`. If the merge rewrites that
   commit (a squash or rebase), re-pin the URL to the merged commit that
   carries the same file (SHA-256 `1e30ddd3...2551a`) and re-render.
3. Set the date, confirm each cited draft revision and that -03 is still
   the latest revision on Datatracker, re-render with the procedure in
   `VALIDATION.md`, and refresh `SHA256SUMS.txt` and `VALIDATION.md`.
4. The provisional `caid` URI scheme is requested through the draft's IANA
   section. Filing it separately with IANA, before an RFC, is a separate
   author action.
