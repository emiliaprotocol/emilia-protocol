# Preprint staging: Authorization Receipts

**Status: READY to post. NOTHING has been posted.** Prepared preprint package.
Posting is the lead's call (account, author metadata, upload).

**Venue:** arXiv (cs.CR) is locked for this topic for us and requires an
endorsement we do not have, so this package targets the **IACR Cryptology ePrint
Archive** as the primary venue — the cryptography community's own preprint server,
verified to accept "Cryptographic protocols" and "Applications" with **no
endorsement or affiliation requirement**, a PDF upload, and CC-BY. It is a better
home than a general CS archive for an authorization-receipt protocol carrying
Tamarin symbolic proofs. **Zenodo** is the zero-friction fallback (CERN-backed,
mints a DOI, no scope moderation).

## What is in this directory

| File | What it is | State |
|---|---|---|
| `main.tex` | Full LaTeX source, faithful to `papers/authorization-receipts-preprint.md` | Built |
| `main.pdf` | Compiled PDF (~22 pages), built from `main.tex` with `tectonic` | Built |
| `STAGING.md` | This checklist | — |

The PDF is the artifact IACR ePrint and Zenodo both host directly (they do not
compile source). `main.tex` is kept for provenance.

## Primary venue — IACR Cryptology ePrint Archive (eprint.iacr.org)

- **Scope:** accepts *Cryptographic protocols* and *Applications* — this paper is
  squarely both (authorization-receipt protocol; Ed25519 + Merkle transparency
  log; Tamarin/TLA+/Alloy analysis).
- **No endorsement / affiliation required** — the exact gate that blocks arXiv cs.CR.
- **Format:** a single PDF (A4 or US-letter) — upload `main.pdf`.
- **License:** CC options incl. CC BY (matches the paper's `CC-BY-4.0`).
- **Moderation:** light human moderation for scope, no peer review; posting is
  typically same/next business day.

**Submission steps (for the lead — DO NOT auto-run):**
1. Log in / create an IACR ePrint submitter account (free, no endorsement).
2. Title + abstract: copy from `main.tex` (`\title{...}` and the abstract env).
3. Category: `Cryptographic protocols` (primary), optionally `Applications`.
   Keywords: authorization receipts, human oversight, transparency log, Tamarin,
   TLA+, formal verification, agent authorization.
4. Publication status: preprint / not published elsewhere.
5. Upload `main.pdf`. License: CC BY 4.0 (matches the source SPDX header).
6. Submit → permanent `eprint.iacr.org/2026/NNNN` id + stable citation.

## Fallback venue — Zenodo (zenodo.org)

If IACR moderation is slow / bounces on scope, or an immediate citable **DOI** is
wanted: Zenodo accepts any research output, no moderation, mints a DOI on publish,
CERN-operated, permanent. Upload `main.pdf` (+ optionally `main.tex`); resource
type *Preprint*; license CC BY 4.0; metadata from `main.tex`. Publish → immediate
DOI. Other options if ever needed: TechRxiv (IEEE), HAL, OSF Preprints.

## Numbers all trace to repo artifacts (no invented figures)

- Conformance 21 suites / 329 vectors → `conformance/conformance-manifest.json`.
- Tamarin core/quorum/composed lemma blocks → `formal/PROOF_STATUS.md` (verbatim);
  10 composed obligations + 2 deliberate falsifications → `lib/proof-stats.json`.
- TLA+ 413,137 states / 26 invariants → `formal/PROOF_STATUS.md`.
- **Alloy 15 + 7 + 6 + 4 = 32 assertions across four CI-gated models** (ep_relations,
  ep_federation, ep_quorum, ep_delegation) at analyzer 6.2.0 →
  `lib/proof-stats.json` `alloy.assertions=32`, `formal/PROOF_STATUS.md`.
- Rust external verifier / 164 vectors / 359 hostility cases →
  `conformance/external/rust-cleanroom-jdieselny.v1.json`, `lib/proof-stats.json`.

## Overclaim discipline verified

- VERIFIED vs ACCEPTED kept separate; reproduction vs independent implementation
  stated (JS/Py/Go are same-team ports, Rust is external interop evidence, zero
  strict independently-attested clean-room acceptances); no "IETF-adopted";
  fail-closed = refuse-with-reason; symbolic scope exclusions stated exactly.

## What was NOT done (honest boundaries)

- **Nothing posted.** No IACR / Zenodo account touched, no upload, no email.
- No co-author list, ORCID, or license *decision* made — the lead's call. Paper is
  currently single-author "Iman Schrock, EMILIA Protocol, Inc."; confirm whether the
  external Rust verifier author is a co-author vs. an acknowledged external party
  (currently the latter).
