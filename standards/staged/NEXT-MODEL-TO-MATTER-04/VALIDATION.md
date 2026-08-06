# Model-to-Matter -04 validation

Validated on 2026-08-06. This packet is staged for human review and has not
been filed. The posted `-03` source and renders remain unchanged.

## Packet checks

- `xmllint --noout`: pass.
- `xml2rfc 3.34.0`: text and HTML renders generated successfully.
- Fresh text and HTML renders: byte-identical to the packet renders.
- `npm run check:model-to-matter-04`: pass. The checker verifies packet
  inventory, revision metadata, doctrine boundaries, implementation-status
  language, render currency, and checksums.
- `idnits 3.1.0 -m submission`: one `SUBMISSION_TYPE_UNEXPECTED` diagnostic.
  The `submissionType="IETF"` attribute is inherited unchanged from the posted
  `-03` source, which was accepted by Datatracker. No other nit was reported.

## Focused implementation checks

- Model-to-Matter Vitest suites: 46/46 tests passed across 3 files.
- `npm run m2m:conformance`: 17/17 `EP-MODEL-TO-MATTER-v1` vectors passed.
- `npm run check:standards-staged`: 6 legacy staged XML sources and 12 renders
  passed their existing checksum and metadata checks.

These implementation checks cover the currently shipped six-role profile. The
new `physical_state_attestation` role is specified by `-04` but is not yet
implemented or claimed by these tests.

## Governed proof snapshot

The committed `lib/proof-stats.json`, generated at
`2026-08-06T16:56:52.671Z`, reports 8,736 test cases across 520 files, 331
conformance vectors, 35 executable security claims, and 20 verified Tamarin
obligations. `TLA2TOOLS_JAR` was not available in this shell, so this task did
not regenerate the governed snapshot. The draft itself makes no proof-count
claim.
