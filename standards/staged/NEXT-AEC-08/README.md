# AEC revision 08 working packet

This directory stages `draft-schrock-ep-authorization-evidence-chain-08`.
It is not published. The last posted revision is -07 (Datatracker posting
2026-09-28T13:23:04Z), whose source is `../NEXT-AEC-07/UPLOAD-THIS/`; the
IETF archive copy of that source has the same SHA-256
(`bfcf111687d6b48cd6b32b829144673c6b70cb340209316dc5a1945a1a62d1e6`). This
packet started from that source byte for byte.

-08 is a focused revision of the requirement expression (Section 8). The
JavaScript parser that accompanied -07 (the one published in
`@emilia-protocol/verify` 6.0.0) and its Python and Go ports already agree
with every corpus vector on syntax validity and Boolean value; -08 makes that
behavior normative and testable, and refuses readings the -07 text permitted:

- token boundaries: the longest run of identifier characters is taken before
  the complete run is classified, so `aORb` is one identifier and `a OR b`
  holds an operator; exact uppercase `AND` and `OR` are the only word
  operators, reserved inside expressions only; identifiers and role
  matching are case-sensitive; SP, HTAB, CR and LF are the only whitespace;
  the ABNF uses RFC 7405 case-sensitive strings;
- validity is separate from truth: an unknown valid identifier is false,
  malformed syntax or an exceeded limit is invalid, both are UNSATISFIED,
  and the whole expression is validated before SATISFIED (the review's
  normative text, Section 8.3, and a new step 4 in Section 9);
- the limits as they are: 4096 UTF-8 octets of the decoded string (a lone
  surrogate counts three octets and is an invalid character), 256 tokens
  counting identifiers, operators and parentheses (a token counts once it is
  complete), 32 levels of nesting, with a deterministic refusal class; an
  evaluator applies exactly these limits, and the expression size is no
  longer a relying-party limit (Sections 8.4 and 5);
- worked examples, including every row of the review's table (Section 8.5);
- a canonical parse and parse identity computed from the tree that is
  evaluated, stated as an interpretation diagnostic: a matching parse
  identity does not guarantee matching verdicts, and the draft does not
  claim every disagreement is caught (Section 8.6);
- the frozen corpus `EP-AEC-EXPRESSION-v1` by commit-pinned URL and
  SHA-256 (Section 8.7);
- evaluator revision `EP-AEC-EVALUATOR-08-v1` and replay migration rules
  (Section 10); the requirement profile digest named as the evidence digest
  of the requirement object, over the expression exactly as stored
  (Section 4); parser differentials in Security Considerations
  (Section 14);
- the Section 10 record template shows `evaluator_profile_digest`, which the
  -07 reference evaluator already emitted and the -07 template omitted; it
  identifies the evaluator profile, which carries the configured limits, and
  Section 10 says the document defines neither a portable serialization of
  that profile nor a closed list of further fact members;
- no wire-format change: EP-AEC-v1, EP-AEC-REQUIREMENT-v1 and
  EP-AEC-REPLAY-v1 keep their versions and the member sets the reference
  evaluator emits; the two CAID examples now use CAID-05's current
  `canactid:` scheme, and no legacy identifier is rewritten.

"Changes in -08" (Section 18) lists the changes.

## Files

- `UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-08.xml`: the
  source.
- `RENDERS/`: the TXT and HTML renderings of that source, produced by
  xml2rfc 3.34.0.
- `SHA256SUMS.txt`: pins the source and both renderings.
- `VALIDATION.md`: the checks run and their results.

## What checks it

`npm run check:aec-08` (`scripts/check-aec-08.mjs`) fails unless:

- the packet holds exactly these three files and the checksums match;
- the source and TXT are printable ASCII with no en or em dash and no TXT
  line over 72 columns, and the TXT carries the -08 name and date;
- the required -08 sentences are in the TXT (and, apart from
  cross-references, in the source), and the -07 grammar, the -07 evaluator
  value, CAID -04, obsolete `caid:` examples and the rejected promises ("cannot happen silently",
  "guarantees matching", "backward compatible") are absent;
- the posted -07 source is unchanged;
- the SHA-256 in Section 8.7 equals the corpus on this tree, its
  `SHA256SUMS` and the locator in `conformance/vectors/README.md`, and,
  when the pinned commit is in the clone, the corpus bytes at that commit;
- the counts in Section 8.7 equal the corpus;
- the reference evaluator on this tree (`packages/verify`, built output)
  emits `EP-AEC-EVALUATOR-08-v1`, has the Section 8.4 limits and the
  Section 8.6 domain separator, reproduces every field of all 104 corpus
  vectors, and reproduces every Table 1 row, the inline parse identity and
  the Section 8.5 limit examples, each of which also agrees with the
  corpus.

`node scripts/check-aec-08.mjs --render` also re-renders the source with
xml2rfc 3.34.0 and requires byte-identical TXT and HTML. CI runs the check
without `--render` (no xml2rfc there).

## Hold

Upload is the editor's decision. Before it:

1. Confirm on Datatracker that -07 is still the latest AEC revision and that
   each cited revision is still the latest (CAID -05, Authorization Receipts
   -13, Quorum -04, AEB -07, Qualification -00). If any moved, update the
   reference, re-render with the procedure in `VALIDATION.md`, refresh
   `SHA256SUMS.txt` and the pins in `scripts/check-aec-08.mjs`.
2. Implementation Status records the current releases checked on 2026-10-06:
   `@emilia-protocol/verify` 7.0.0, Python `emilia-verify` 2.9.0, and Go
   `packages/go-verify/v2.5.0`. Recheck them immediately before upload and
   revise the paragraph if any package has moved.
3. Section 8.7 cites the corpus at commit `2ebba2d84` on
   `aec-08-expression-integrity`. That commit must stay reachable on the
   public repository or the URL may stop resolving; the SHA-256 remains the
   identity either way. The `main merge queue` ruleset merges with
   `merge_method: MERGE`, which keeps the branch commits, and so the commit,
   reachable from `main`; do not squash or rebase this branch around the
   queue.
4. Post one reviewed XML, then verify the archived bytes against
   `SHA256SUMS.txt` before marking -08 published.
