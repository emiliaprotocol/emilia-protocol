# Preprint staging: Authorization Receipts

**Status: READY to post. NOTHING has been posted.** This directory is a prepared
preprint package. Posting is the lead's call (account, author metadata, upload).

**Venue change:** arXiv (cs.CR) is locked for this topic for us, so this package
targets the **IACR Cryptology ePrint Archive** as the primary venue — the
cryptography community's own preprint server, which is a *better* fit for an
authorization-receipt protocol carrying Tamarin symbolic proofs than a general
CS archive. **Zenodo** is the zero-friction fallback (CERN-backed, mints a DOI,
no scope moderation). Both are covered below.

## What is in this directory

| File | What it is | State |
|---|---|---|
| `main.tex` | Full LaTeX source, faithful carriage of `papers/authorization-receipts-preprint.md` at HEAD | Built |
| `main.pdf` | Compiled PDF, 22 pages, from `main.tex` | Built with `tectonic` this session |
| `STAGING.md` | This checklist | — |

The PDF is the artifact IACR ePrint and Zenodo both want (they host a PDF, they
do not compile source). `main.tex` is kept for provenance and for any venue that
prefers source.

## PDF build — actually run this session

Built with **`tectonic`** (the only LaTeX engine on this machine; no
`pdflatex`/`xelatex`/MacTeX). Command run in this directory:

```
tectonic main.tex
```

Output: `main.pdf`, 22 pages, ~123 KiB. Clean build. One residual 20.06pt
overfull `\hbox` (a hyphenated compound in Section 3.2 prose) — cosmetic, well
inside typesetting tolerance. No errors. `main.tex` uses only stock TeX Live
packages (`geometry`, `amsmath`, `amssymb`, `textcomp`, `microtype`, `enumitem`,
`fancyvrb`, `parskip`, `hyperref`, `xurl`, `seqsplit`, `lmodern`), so it rebuilds
unchanged anywhere; the hosted PDF is what gets uploaded, so engine parity is not
on the critical path for IACR ePrint / Zenodo.

## Primary venue — IACR Cryptology ePrint Archive (eprint.iacr.org)

Verified against `eprint.iacr.org/submit.html` this session:

- **Scope**: accepts *Cryptographic protocols* and *Applications* — this paper is
  squarely both (authorization-receipt protocol; Ed25519 + Merkle transparency
  log; Tamarin/TLA+/Alloy analysis).
- **No endorsement or institutional affiliation required.** This is the exact gate
  that blocks arXiv cs.CR; IACR ePrint does not have it.
- **Format**: a single **PDF** (A4 or US-letter). Upload `main.pdf`.
- **License**: six CC options incl. **CC BY** (matches the paper's declared
  `CC-BY-4.0`) and CC0.
- **Moderation**: light human moderation for scope/plausibility, no peer review;
  posting is typically same/next business day. Cryptographic-protocol papers with
  formal analysis are core scope, so scope risk is low.

**Submission steps (for the lead — DO NOT auto-run):**

1. Create/log in to an IACR ePrint submitter account (an IACR account; free, no
   endorsement).
2. Metadata: title + abstract — copy from `main.tex` (`\title{...}` and the
   `abstract` environment; the abstract has no TeX macros, pastes cleanly).
3. **Category**: `Cryptographic protocols` (primary); optionally add
   `Applications`. **Keywords**: authorization receipts, human oversight,
   transparency log, Tamarin, TLA+, formal verification, agent authorization.
4. **Publication status**: "preprint / not published elsewhere."
5. **Upload** `main.pdf`.
6. **License**: select **CC BY 4.0** (matches the source header). Change the SPDX
   header in `main.tex` first if a different license is wanted, so they agree.
7. Confirm the non-exclusive license grant and submit. ePrint assigns a permanent
   `eprint.iacr.org/2026/NNNN` id and a stable citation.

## Fallback venue — Zenodo (zenodo.org)

If IACR ePrint moderation is slow or bounces on scope, or if a citable **DOI** is
wanted immediately: **Zenodo** accepts any research output, no moderation, mints a
DOI on publish, CERN-operated, permanent.

- Upload `main.pdf` (and optionally `main.tex` as an additional file).
- Resource type: *Preprint*. License: **CC BY 4.0**.
- Metadata: title/authors/abstract from `main.tex`; keywords as above.
- Publish -> immediate DOI (e.g. `10.5281/zenodo.NNNNNNN`), citable at once.

Other domain-adjacent options if ever needed: **TechRxiv** (IEEE engineering
preprints), **HAL** (open archive), **OSF Preprints** (general). IACR ePrint is
the right first choice for this specific paper.

## Every quantitative claim traces to a repo artifact (no invented numbers)

| Claim in paper | Value | Repo source |
|---|---|---|
| Conformance suites / vectors | 18 / 251 | `conformance/conformance-manifest.json` -> `totals.suites=18`, `totals.vectors=251` (manifest and proof-stats now agree) |
| Tamarin core / quorum / composed lemma blocks | verbatim | `formal/PROOF_STATUS.md` (byte-for-byte) |
| Ten strict composed lemmas verified; 2 deliberate falsifications | 10 / 2 | `formal/PROOF_STATUS.md`; `lib/proof-stats.json` `tamarin.verifiedObligations=10`, `deliberatelyUnsafeCounterexamples=2` |
| TLA+ states / distinct / invariants | 413,137 / 45,342 / 26 | `formal/PROOF_STATUS.md`; `lib/proof-stats.json` `tla.invariants=26` |
| Alloy assertions | 15 + 7 = 22 | `formal/PROOF_STATUS.md`; `lib/proof-stats.json` `alloy.assertions=22` |
| Rust external verifier commit / tree | `7faba360…` / `0553c5fa…` | `conformance/external/rust-cleanroom-jdieselny.v1.json` |
| Rust clean-room bundle / hostility | 16-suite / 164-vector; 353 + 6 | `conformance/external/rust-cleanroom-jdieselny.v1.json`; `lib/proof-stats.json` `externalImplementation.vectors=164`, `hostilityCases=359` |
| External reproduction (COSA / J Diesel NY) | 158 vectors | EP-EXTERNAL-VERIFICATION-STATEMENT record |

**Count note (now consistent):** the earlier `proof-stats.json conformance.vectors`
staleness (232 vs manifest 251) was resolved when the count files were re-synced
this session; both now report **251**, matching the paper. No open discrepancy.

## Overclaim discipline verified (the paper does NOT do any of these)

- **VERIFIED vs ACCEPTED** kept separate (Section 5 B3; Section 6.4). Not conflated.
- **Reproduction vs independent implementation**: Section 8 — JS/Python/Go ports
  are "same-team ports … not three independent implementations"; COSA is a
  "historical reproduction result"; the Rust verifier is "external interoperability
  and parser-robustness evidence" with "zero strict independently attested
  clean-room acceptances." No independence upgrade.
- **No "IETF-adopted"**: Internet-Drafts are "individual submissions with no
  working-group status" and "work in progress."
- **fail-closed** used only as refuse-with-reason (Section 6.3), never "throws".
- Symbolic scope exclusions stated exactly (Section 7.4).

## What was NOT done (honest boundaries)

- **Nothing posted.** No IACR/Zenodo account touched, no upload, no email.
- No co-author list, ORCID, or license *decision* made — the lead's call. The
  paper is currently single-author "Iman Schrock, EMILIA Protocol, Inc."; confirm
  whether any contributor (e.g. the external Rust verifier author) should be a
  co-author vs. an acknowledged external party (currently the latter).
- PDF built with `tectonic`, not verified against arXiv's engine — irrelevant to
  IACR/Zenodo, which host the PDF directly.
