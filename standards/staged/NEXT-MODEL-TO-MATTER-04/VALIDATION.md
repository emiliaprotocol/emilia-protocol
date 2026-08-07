# Model-to-Matter -04 validation

Validated and published on 2026-08-06. The immutable IETF archive XML is
byte-identical to the retained source. The superseded `-03` source and renders
are preserved under `standards/archive/`.

## Packet checks

- `xmllint --noout`: pass.
- `xml2rfc 3.34.0`: text and HTML renders generated successfully.
- Fresh text and HTML renders: byte-identical to the packet renders.
- `npm run check:model-to-matter-04`: pass. The checker verifies packet
  inventory, revision metadata, doctrine boundaries, implementation-status
  language, render currency, and checksums.
- `idnits 3.1.0 -m submission`: pass, no nit reported.

## Focused implementation checks

- Model-to-Matter Vitest suites: 51/51 tests passed across 4 files.
- `npm run m2m:conformance`: 25/25 `EP-MODEL-TO-MATTER-v1` vectors passed.
- `npm run check:standards-staged`: 6 legacy staged XML sources and 12 renders
  passed their existing checksum and metadata checks.

These checks cover the seven-role profile, canonical physical-measurement
window, control-domain and key separation, negative and stale measurements,
role substitution, measurement replay state, and the compiled Reliance Program
and evidence-requirement digests bound into the clearance object. They use
synthetic inputs and do not establish physical truth or wet-lab performance.

## Governed proof snapshot

The committed `lib/proof-stats.json`, generated at
`2026-08-06T22:10:31.054Z`, reports 8,741 test cases across 521 files, 331
conformance vectors, 35 executable security claims, and 20 verified Tamarin
obligations. The pinned TLA+ tools v1.7.4 checker also re-verified the current
seven-leg effect-profile model: 2,517,121 states generated, 453,600 distinct,
zero left on queue, and no invariant violation. The draft itself makes no
proof-count claim.
