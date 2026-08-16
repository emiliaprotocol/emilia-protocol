# Focused IACR ePrint revision

This directory contains the focused authorization-protocol revision prepared after the IACR ePrint rejections of temporary submissions `xxxx/111011` and `xxxx/111097`.

The revision removes implementation totals, standards status, product narrative, and evidence-graph material that obscured the security result. The paper presents Action-Bound Injective Authorization as a protocol property against a signer-harvesting collector, expands the concrete reduction into games G0 through G4 with an explicit per-key forger, adds named attacks and necessity propositions, proves a separate 2-of-2 quorum corollary, and separates the cryptographic reduction from the linearizable admission assumption.

The 16 August correction makes the transplantation game semantic rather than byte-only. The signing interface is now `SignCtx(j,x)` and the experiment records `(j,x,m(x))`, so a different context that maps to the same bytes remains a transplant instead of disappearing into the EUF-CMA query table. The later-reveal result is named and scoped as trace-prefix authenticity, not forward integrity. The related-work section now covers secure formats, transparency overlays, forward-secure audit logs, and formal web-authorization analysis.

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

All three pinned runners were executed again on 16 August 2026. The receipt-core runner verified five obligations, including the 12-step later-reveal prefix lemma, and reproduced the deliberate 11-step falsification without consumption. All five quorum-core obligations verified. The composed runner verified 20 positive obligations and reproduced all eight deliberate negative controls.

## Publication state

This manuscript is the published v3 successor to the live Zenodo v2 record `10.5281/zenodo.21520973`, under the all-versions concept DOI `10.5281/zenodo.21520972`. Zenodo published version DOI `10.5281/zenodo.21968577` on 16 August 2026. The rejected IACR ePrint PDF was not reused.

## Final artifact

The final PDF is 19 pages and 172,068 bytes. Two clean builds made with the command above were byte-identical.

`SHA-256: f158dbcd36f8831cc8f39aa7d37cfd505679483b57b29bb33dc676a9af75867e`
