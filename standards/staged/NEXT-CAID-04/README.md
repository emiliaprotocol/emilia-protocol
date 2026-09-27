# CAID revision 04 working packet

This directory stages `draft-schrock-canonical-action-identifier-04`. It is
not published. The last posted revision is -03, whose exact source is kept
in `../NEXT-CAID-03/`. This packet started from that source.

-04 is a substantive revision. It makes the processing model complete and
machine-checkable: strict JSON text input, host values, one data model with
one limits table, definition conformance, `definition_sha256` and
resolution, code fields with named formats, the monotone enum advance, a
fixed reason order with verification details, normative mapping stages, a
rewritten Security section, a new Privacy section, six IANA registries and
a provisional `caid` URI scheme, and an Implementation Status section. The
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
  and the compiled code formats. `node scripts/check-caid-04.mjs --emit`
  prints them for editing.
- Every value in Appendix C, the Section 3.3 identifier example, and the
  tool.call.1 example recompute, through `caid/spec/reference.mjs` and
  through hashing done in the script.
- Every `chg-` item maps to vector ids that exist in the corpora.
- The normative references, registry version 5 and its counts and file
  digest, the prose examples against the ABNF, the removed -03 text, both
  renders, and the checksums.

## Hold

Submission is the author's decision. Before it:

1. Corpus version 5 must carry every vector id in `CHANGES-VECTORS.json`.
   Until it does, `check-caid-04` fails with the list of missing ids and
   nothing else.
2. The JavaScript, Python, and Go implementations must implement the -04
   features, so that the Implementation Status section is true when the
   draft posts. That includes refusing Unicode noncharacters, which -04
   excludes from the data model by profiling I-JSON.
3. Set the date, confirm each cited draft revision and that -03 is still
   the latest revision on Datatracker, re-render with the procedure in
   `VALIDATION.md`, and refresh `SHA256SUMS.txt` and `VALIDATION.md`.
4. The provisional `caid` URI scheme is requested through the draft's IANA
   section. Filing it separately with IANA, before an RFC, is a separate
   author action.
