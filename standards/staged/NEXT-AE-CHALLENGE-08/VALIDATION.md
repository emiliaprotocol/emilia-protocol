# Validation record

Candidate prepared on 2026-08-26 from the byte-verified published -07 XML.
The following checks were reproduced locally on 2026-08-27 after rebasing the
candidate onto repository main at `3ef70d091`. Governed checks used Node
v24.18.0 and the repository-pinned TLC 2.19 jar whose SHA-256 is
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS. Regeneration retained four
  line-length warnings for complete `sha256:` values in copyable JSON.
- `idnits 3.1.0 -m submission`: PASS with one warning covering those four
  over-long JSON lines.
- `npm run check:ae-challenge-08`: PASS for the isolated packet, rendered
  outputs, checksums, and immutable -07 lineage.
- `npm run check:standards-staged`: PASS.
- `npm run check:repository-boundary`: PASS.
- `npm run check:public-conformance-claims`: PASS.
- `npm run security-case:emit`: PASS, 35 executable claims and 259 hashed
  evidence files.
- `npm run sync:proof-stats`: PASS. Its governed measurement executed 10,582
  tests across 654 files and re-executed the security case. It records 78
  selected formal/runtime scenarios, 51 paired negative controls, and 21
  claims.
- `npm run sync:llm-context` followed by `npm run check:llm-context`: PASS.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for the final XML, HTML, and TXT
  bytes.
- `git diff --check`: PASS.

TypeScript compilation and the production web build were not rerun for this
documentation-only repair and are not claimed in this record.

Runtime/conformance implementation is not claimed by this revision. A hostile
implementation pass showed that correct lineage issuance must be integrated
with authoritative challenge registration, audience checking, atomic
consumption, and profile-derived authenticated digests. A standalone record
constructor was therefore withheld rather than presented as conformant.

The existing formal evidence-challenge lifecycle does not by itself prove
evaluation-lineage immutability or policy-transition properties.

The immutable published -07 XML SHA-256 is
`2bfb675ec652487bd90addbb95dda15551e69f4c022fc83a45195fee6d8d8e34`.
