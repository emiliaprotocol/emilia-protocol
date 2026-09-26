# CAID revision 04 working packet

This directory stages `draft-schrock-canonical-action-identifier-04`. It is not
published. Datatracker's latest revision is -03, published on 2026-09-26; its
exact source is retained in `../NEXT-CAID-03/`, and this packet starts from
that source.

- The working source is
  `UPLOAD-THIS/draft-schrock-canonical-action-identifier-04.xml`.
- `RENDERS/` contains the TXT and HTML review renderings generated from that
  XML.
- `SHA256SUMS.txt` pins the source and both renderings.
- `VALIDATION.md` records the checks and the exact hold state.

Revision -04 so far carries two clarifications.

- The amount-string prose becomes ABNF that matches what the reference
  implementations and the shared corpus enforce: the whole string matches,
  and the integer part has no leading zero other than a lone "0". A string
  that fails the rule is `invalid_amount:<name>` and a non-string value is
  `mistyped_field:<name>`, where -03 allowed either reason. The type
  definition schema now states that field notes never change validation.
- An unknown suite is defined as one not in the suite registry. A registered
  suite that an implementation does not implement still parses, and
  computation and verification report it as `unknown_suite`; the
  Verification section now names that reason, which -03 left unstated. The
  Identifier Syntax section lists the 16 final digest characters whose
  unused bits are zero. The identifier grammar and the other parsing rules
  are unchanged since -00. The reference parsers had accepted a suite
  outside the registry, a suite beginning with a digit, and a digest whose
  final character sets an unused bit; they now refuse all three, and corpus
  version 4 holds all three ports to it.

Neither change alters the CAID of any Action Object that the reference
implementations accept.

Registry field notes are unchanged. They are informative, the grammar is
defined by the field type, and the registry v4 file is pinned by SHA-256 in
the WIMSE CAID scope profile, the CAID/AEC/AEB capsule manifest, and the COAZ
translation source lock. Rewriting a note would change those pinned bytes
without changing any validation result.

Hold: whether these clarifications justify a Datatracker revision is the
author's decision. Before submission, set the
date, confirm each cited draft revision against Datatracker (-03 deliberately
retained its earlier citations), re-render, and refresh `SHA256SUMS.txt` and
`VALIDATION.md`. Publication is a separate author action.
