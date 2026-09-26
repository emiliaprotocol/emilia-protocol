# CAID revision 03 working packet

This directory staged `draft-schrock-canonical-action-identifier-03` for
review. Datatracker published it on 2026-09-26, and it is retained as
exact-submission provenance. Later changes are staged in `../NEXT-CAID-04/`.

- The submitted file was
  `UPLOAD-THIS/draft-schrock-canonical-action-identifier-03.xml`; the IETF
  archive copy is byte-identical to it.
- `RENDERS/` contains the TXT and HTML review renderings generated from that
  XML.
- `SHA256SUMS.txt` pins the source and both renderings.
- `VALIDATION.md` records the checks and the exact hold state.

Revision -03 makes external enum validation replayable: a definition must pin
an immutable snapshot label and SHA-256 digest, resolution is local and exact,
and bare, unresolved, mismatched, or out-of-set values fail closed. It makes
the enum definition forms exact, requires own-member field presence, and makes
RFC 8785's refusal of unpaired surrogates explicit. It records the reference
registry's v3-to-v4 migration: CAID bytes are unchanged for existing action
objects whose values are in the pinned set, codes outside it now refuse, and
eleven registered types cannot compute until their external value sets are
pinned.

Revision -03 is an individual Internet-Draft. Do not describe it as adopted
or endorsed by the IETF.
