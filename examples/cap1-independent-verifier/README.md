# Independent CAP-1 verifier

This directory contains an EMILIA-authored verifier for Joel David Hillier's
Coverage Attestation Profile, CAP-1. It was constructed from
`draft-hillier-coverage-attestation-00` and the accompanying normative JSON
Schema, without reading or porting the three Certisyn verifier
implementations.

The source is pinned to Certisyn commit
`0980d3201aa2caab3cbad5c6e9bc99b422370b43`. The exact five positive and ten
negative vectors from that commit are preserved under `vectors/upstream/`.
`source-lock.json` records the source and individual SHA-256 digests.

Run the exact upstream class and EMILIA controls:

```bash
node --test examples/cap1-independent-verifier/run.test.mjs
node examples/cap1-independent-verifier/run.mjs path/to/cap-1.json
```

The base verifier returns CAP-1 conformance only. It does not establish that
the producer told the truth, that the stated population was complete, or that
the examined units were distinct. `verifyExaminedSetEvidence` is a separate,
optional relying-party control that verifies canonical eligible and examined
set commitments plus one digest-bound result per examined unit. Its verdict
must not be presented as CAP-1 conformance.

The current CAP-1 text also creates a semantic conflict for `withheld`: the
stratum model calls every `unexamined` entry not examined, while the
disposition defines `withheld` as examined with an undisclosed result. The
optional examined-set control refuses that case by name until the specification
selects one meaning.

See [NOTICE.md](NOTICE.md) for attribution and license information.
