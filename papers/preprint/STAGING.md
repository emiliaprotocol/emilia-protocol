# Preprint staging: Action-Bound Injective Authorization

**Status: APPROVED FOR IACR RESUBMISSION AFTER MATERIAL SECURITY-ARGUMENT
REPAIR; COMPLETE LOCAL PACKAGE GATES PASSED ON 10 AUGUST 2026.**
Historical submission `xxxx/110952` was received on 5 August 2026 PT and rejected
on 6 August 2026 with the editor's note: "Unclear or insufficient contribution
to the field of cryptology." No public ePrint number was assigned. The revised
package was submitted as `xxxx/110966` on 6 August 2026 PT and its author email
was confirmed, then rejected because it lacked security proofs or convincing
security arguments. No public ePrint number was assigned. The current working
package responds materially: it defines the Action-Bound Injective Authorization
(ABIA) experiment, states a computational reduction with explicit
non-cryptographic assumptions, removes replay properties that had been assumed
as Tamarin restrictions, uses linear protocol state instead, and adds a shared,
independently issued authorization instance to prevent cross-ceremony quorum
splicing. The repaired package passed `preprint:build`, `check:preprint`, and
`test:preprint` on 10 August 2026. The rejection remains a venue decision rather
than peer review, but its security-argument criticism is treated as correct.

The exact PDF submitted as `xxxx/110966` is preserved by git commit `a56b0bea`
with SHA-256 `99d667231d9c596920bdf8ad7c445a26d7211e84606b6bd2b0ca8b27114449e5`.
The current working source is materially different from the rejected package.
The checked submission artifact is `main.pdf`, 27 pages, SHA-256
`f851d7e8a7ccf472d22a04eef8707743d446d30300d2c7d48cf505d4bea2bc9b`.

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
| `main.tex` | Full LaTeX source carrying the canonical Markdown fingerprint and current repo evidence claims | Rebuilt locally; claim-checker gated |
| `main.pdf` | Compiled PDF, built from `main.tex` with `tectonic` | Working copy only; not approved for submission |
| `STAGING.md` | This checklist | — |

The PDF is the artifact IACR ePrint and Zenodo both host directly (they do not
compile source). `main.tex` is kept for provenance.

## Reproduce and verify locally

Prerequisites: Node.js 20 or newer, Tectonic 0.16.9 or compatible, and Poppler's
`pdftotext`. From the repository root:

```sh
npm run preprint:build
npm run check:preprint
npm run test:preprint
```

`check:preprint` derives selected evidence-bearing claims from the live
conformance manifest, proof ledger, proof statistics, standards status, and
pinned external-verifier evidence. It checks declared source fingerprints and
those claims in `main.tex`, extracted `main.pdf` text, and this staging record.
It is not a complete semantic comparison of every TeX paragraph to the PDF.
Run `preprint:build` first to prove the PDF derives from the checked-in TeX;
passing the checker then establishes local evidence synchronization only, not
publication approval or venue acceptance. The build command fixes
`SOURCE_DATE_EPOCH` to `2026-07-19T00:00:00Z`; repeated builds from identical
source with the same Tectonic toolchain are byte-identical.

## Primary venue — IACR Cryptology ePrint Archive (eprint.iacr.org)

- **Scope:** accepts *Cryptographic protocols* and *Applications* — this paper is
  squarely both (authorization-receipt protocol; Ed25519 + Merkle transparency
  log; Tamarin/TLA+/Alloy analysis).
- **No endorsement / affiliation required** — the exact gate that blocks arXiv cs.CR.
- **Format:** a single PDF (A4 or US-letter) — upload `main.pdf`.
- **License:** CC options incl. CC BY (matches the paper's `CC-BY-4.0`).
- **Moderation:** light human moderation for scope and contribution, no peer
  review; posting is not guaranteed by a conformance or implementation record.

**Future resubmission metadata (only after an explicit approval gate):**
1. Author: Iman Schrock; ORCID `0009-0004-0290-5433`; affiliation EMILIA
   Protocol, Inc.; public contact `team@emiliaprotocol.ai`.
2. Category: `Cryptographic protocols`.
3. Publication history: major revision of the earlier Zenodo preprint,
   DOI `10.5281/zenodo.21520973`.
4. License: CC BY.
5. PDF: the checker-gated 27-page `main.pdf` in this directory.
6. Prior submission: `xxxx/110966`; author email ownership was confirmed, then
   the package was rejected. The private confirmation code remains only in the
   author's IACR email, not this repo.

## Fallback venue — Zenodo (zenodo.org)

If IACR moderation is slow / bounces on scope, or an immediate citable **DOI** is
wanted: Zenodo accepts any research output, no moderation, mints a DOI on publish,
CERN-operated, permanent. Upload `main.pdf` (+ optionally `main.tex`); resource
type *Preprint*; license CC BY 4.0; metadata from `main.tex`. Publish → immediate
DOI. Other options if ever needed: TechRxiv (IEEE), HAL, OSF Preprints.

## Numbers all trace to repo artifacts (no invented figures)

- Conformance 21 suites / 331 vectors → `conformance/conformance-manifest.json`.
- Current cited drafts → `standards/STATUS.json`: Authorization Receipts -11,
  Quorum -03, Authorization Evidence Chain -05, Evidence Record -01.
- Tamarin core/quorum/composed lemma blocks → `formal/PROOF_STATUS.md` (verbatim);
  20 composed obligations + 8 deliberate falsifications → `lib/proof-stats.json`.
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

## Current publication boundary

- The prior paper was rejected by IACR and is not public; it did not receive a
  permanent `eprint.iacr.org/2026/NNNN` identifier.
- The second package, `xxxx/110966`, was rejected. The current security analysis
  is a material repair made after that decision and has not been submitted.
- A future upload requires a clean reviewed commit, reproducible PDF build,
  passing `npm run check:preprint` and `npm run test:preprint`, and fresh explicit
  submission approval from the author.
- The paper remains single-author: Iman Schrock, EMILIA Protocol, Inc. The
  external Rust verifier author remains an acknowledged external implementation
  party, not a co-author.
