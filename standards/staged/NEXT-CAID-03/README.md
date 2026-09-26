# CAID revision 03 working packet

This directory stages `draft-schrock-canonical-action-identifier-03` for
author review and submission. It is not yet published; the Datatracker copy of
revision -02 remains the latest public revision.

- The file to submit after review is
  `UPLOAD-THIS/draft-schrock-canonical-action-identifier-03.xml`.
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

Publication remains a separate author action. Do not describe these staged
files as an IETF publication until Datatracker accepts revision -03.
