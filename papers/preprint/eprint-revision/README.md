# Focused IACR ePrint revision

This directory contains the cryptology-focused revision prepared after the rejection of temporary submission `xxxx/111011` on 15 August 2026.

The revision removes implementation totals, standards status, product narrative, and evidence-graph material that obscured the security result. The paper presents Action-Bound Injective Authorization as a protocol property against a signer-harvesting collector, expands the concrete reduction into games G0 through G4 with an explicit per-key forger, adds named attacks and necessity propositions, proves a separate 2-of-2 quorum corollary and an acceptance-prefix integrity property, and separates the cryptographic reduction from the linearizable admission assumption.

## Build

Prerequisites: Tectonic and Poppler's `pdftotext`.

```sh
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build main.tex
cp build/main.pdf main.pdf
node check.mjs
```

## Evidence scope

The paper cites the four existing repository models:

- `formal/tamarin/ep_receipt_core.spthy`
- `formal/tamarin/ep_quorum_core.spthy`
- `formal/tamarin/ep_reliance_composed.spthy`
- `formal/tamarin/ep_six_claim_composed.spthy`

The exact machine-checked results are recorded in `formal/PROOF_STATUS.md`, `formal/tamarin/README.md`, and [`VERIFICATION.md`](VERIFICATION.md). The repository-pinned rerun scripts use Tamarin 1.10.0 and Maude 3.4 in Docker.

Both pinned runners were executed again on 15 August 2026. The receipt-core runner verified five obligations, including the new 12-step later-reveal prefix lemma, and reproduced the deliberate 11-step falsification without consumption. All five quorum-core obligations verified.

## Publication state

The author approved a fresh submission on 15 August 2026. The source and PDF remain preparation artifacts until the exact final package is verified and actually uploaded; the rejected PDF is not reused.

## Final artifact

The final PDF is 18 pages and 165,866 bytes. Two clean builds made with the command above were byte-identical.

`SHA-256: 0f5bdabe86ce164341d7cad8eb5f71574ef12834267050517813e51213fba24a`
