# GRACE -01 review candidate

This directory contains a **review candidate** for
`draft-schrock-kintzele-grid-curtailment-01`. It is derived from the published
`-00` review source without modifying that packet. It has not been submitted to
the IETF and is not an instruction to upload or publish anything.

The candidate applies the architecture agreed by the four collaborators:

1. EMILIA is the exact-action authority, admission, and one-time-consumption
   spine.
2. A proof from `draft-morrison-ot-command-authority` is upstream,
   action-specific command-authority evidence. It binds the agent, principal,
   asset, control verb, and expiry, but is not sufficient dispatch authority by
   itself.
3. COSA, or another pinned executor adapter, supplies downstream
   command-channel acknowledgment after admission.
4. A separately authenticated meter supplies observed-effect evidence.
5. Hardwired trips and interlocks remain outside every protocol path.

It also adapts Justin Kintzele's RDU101 material as a non-normative worked
example. The example preserves the central limit: the hardware was
characterized read-only, and no energized actuation test is claimed.

## Contents

- `REVIEW-SOURCE/`: editable RFCXML source.
- `RENDERS/`: generated text, HTML, and local-review PDF.
- `WORKING-OUTLINE.md`: the agreed revision structure and ownership split.
- `OPEN-COAUTHOR-INPUTS.md`: decisions still required before the text is ready
  for coauthor approval.
- `VALIDATION.md`: exact local validation record and known tool limitation.
- `SHA256SUMS.txt`: checksums for this staged packet, excluding the manifest.

## Rebuild and validate

```sh
xml2rfc --text --html --path \
  standards/staged/NEXT-GRID-CURTAILMENT-01/RENDERS \
  standards/staged/NEXT-GRID-CURTAILMENT-01/REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-01.xml

node scripts/check-grace-01-candidate.mjs
```

The PDF is a local browser print of the generated HTML because the repository's
xml2rfc environment does not include WeasyPrint's native PDF dependencies. It
is for review convenience; the RFCXML, text, and HTML are the normative packet
inputs.
