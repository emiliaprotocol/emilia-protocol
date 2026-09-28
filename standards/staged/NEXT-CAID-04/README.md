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

## Hold

Submission is the author's decision. Before it:

1. The Implementation Status section points at `tree/main/caid` and says
   all three implementations implement -04. Pull request #821 merged as
   `cea10b85e`, but this packet's branch (`feat/caid-04-prefiling`) also
   carries the JavaScript mapping stage B fix that the draft's Section 8.3
   now states, the Go back-reference fix that Sections 2.2 and 2.5 state,
   the JavaScript fix (in the vendored copy too) that reads a host array
   of 2^24 or more elements, which Section 2.5 admits within the value
   count, the conditional cbor-sha256 vectors and the runners that skip
   them, the vectors its change log cites (and the mapping runners' `host`
   and `fill` mutations that some of them need), and the `caid.abnf`
   comment that Appendix A carries. Merge this branch before filing. The
   branch has merged main at `dedd9a24d`; if main moves again, merge it
   and regenerate `AI_CONTEXT.md`, `public/llms-full.txt` and
   `public/.well-known/emilia-context.json` with
   `node scripts/generate-llm-context.mjs --write` (both sides change their
   input digest line, so a textual merge conflicts), then confirm with
   `npm run check:llm-context`. After `git fetch origin`, run
   `node scripts/check-caid-04.mjs --prefiling`. It fails today, as it
   should. It requires that origin/main is the remote main
   (`git ls-remote`), that it carries registry version 5,
   `caid/spec/caid.abnf` and the -04 ports, that the [CAID-REGISTRY]
   commit is reachable from origin/main, that origin/main's `caid/` tree
   and `packages/verify/vendor/caid.mjs` equal this branch's byte for byte,
   and that the renders equal a fresh `xml2rfc 3.34.0` render. It lists
   every file that differs from main.
2. [CAID-REGISTRY] is pinned to commit
   `cea10b85e96460a04bf55d683a1ebc34e8b2c9a6`, the merge of #821 on main,
   whose `caid/registry/action-types.json` is registry version 5 (SHA-256
   `1e30ddd3...2551a`). The reference targets the raw file URL at that
   commit, whose octets the digest covers, and names no blob URL.
3. Set the date, confirm each cited draft revision and that -03 is still
   the latest revision on Datatracker, re-render with the procedure in
   `VALIDATION.md`, and refresh `SHA256SUMS.txt` and `VALIDATION.md`.
4. The `caid` URI scheme is requested as Permanent through the draft's
   IANA section. An early review request to uri-review@ietf.org (RFC 7595,
   Section 7.1) is a separate author action.
