# Memory Projection Record -01 coauthor review packet

This directory is a coauthor-review packet, not a Datatracker upload queue.
Nothing here authorizes submission.

The candidate `-01` keeps the `MEMORY-PROJECTION-RECORD-v1` wire field set
and signature domain unchanged. It closes the two source-profile
underspecifications exposed by the ApertoMemory and EMILIA reciprocal
implementation work:

- the deterministic-CBOR ApertoMemory trust snapshot; and
- the exact `urn:apertomemory:context-frame:v0` UTF-8 fragment bytes.

The source-profile rules are pinned to ApertoMemory commit
`48be5250f26aea9e34bc4f8adaca22ac9016cc84`. The implementation-status text
records only the bounded checks completed by both projects. It does not claim
blanket ApertoMemory conformance, model receipt or use, action authorization,
execution, or outcome.

## Review files

- `draft-ferro-schrock-memory-projection-record-01.xml`
- `draft-ferro-schrock-memory-projection-record-01.txt`
- `draft-ferro-schrock-memory-projection-record-01.html`
- `SHA256SUMS.txt`

## Validation

- `xmllint --noout`: pass
- `xml2rfc 3.34.0`: XML rendered to TXT and HTML
- `npm run memory-projection:conformance`: 38/38 pass
- `npm run check:repository-boundary`: pass
- `npm run check:standards-staged`: pass
- `npm run check:llm-context`: pass
