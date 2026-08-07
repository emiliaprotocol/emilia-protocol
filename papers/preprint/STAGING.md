# Preprint staging: Action-Bound Injective Authorization

**Status: SUBMITTED TO IACR; EMAIL CONFIRMED; AWAITING EDITOR REVIEW.**
Historical submission `xxxx/110952` was received on 5 August 2026 PT and rejected
on 6 August 2026 with the editor's note: "Unclear or insufficient contribution
to the field of cryptology." No public ePrint number was assigned. The revised
package was submitted as `xxxx/110966` on 6 August 2026 PT and its author email
was confirmed. The revision now foregrounds the named Action-Bound Injective
Authorization (ABIA) security definition, its signer-harvesting adversary, its
symbolic theorem, and the counterexample separations that distinguish protocol
authorization from ordinary signature authenticity. The rejection remains
recorded as a venue decision, not as a peer-review finding.

The exact PDF submitted as `xxxx/110966` is preserved by git commit `a56b0bea`
with SHA-256 `99d667231d9c596920bdf8ad7c445a26d7211e84606b6bd2b0ca8b27114449e5`.
The current working PDF changes only the cited engineering draft from
Authorization Receipts-09 to the subsequently published -10. It has not been
resubmitted while the confirmed package remains under editor review.

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
| `main.pdf` | Compiled PDF (25 pages), built from `main.tex` with `tectonic` | Current citation-synchronized working copy; exact submitted bytes are pinned above |
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

**Resubmission metadata:**
1. Author: Iman Schrock; ORCID `0009-0004-0290-5433`; affiliation EMILIA
   Protocol, Inc.; public contact `team@emiliaprotocol.ai`.
2. Category: `Cryptographic protocols`.
3. Publication history: major revision of the earlier Zenodo preprint,
   DOI `10.5281/zenodo.21520973`.
4. License: CC BY.
5. PDF: the checker-gated 25-page `main.pdf` in this directory.
6. Submission: `xxxx/110966`; author email ownership confirmed; awaiting editor
   review. The private confirmation code remains only in the author's IACR email,
   not this repo.

## Fallback venue — Zenodo (zenodo.org)

If IACR moderation is slow / bounces on scope, or an immediate citable **DOI** is
wanted: Zenodo accepts any research output, no moderation, mints a DOI on publish,
CERN-operated, permanent. Upload `main.pdf` (+ optionally `main.tex`); resource
type *Preprint*; license CC BY 4.0; metadata from `main.tex`. Publish → immediate
DOI. Other options if ever needed: TechRxiv (IEEE), HAL, OSF Preprints.

## Numbers all trace to repo artifacts (no invented figures)

- Conformance 21 suites / 331 vectors → `conformance/conformance-manifest.json`.
- Current cited drafts → `standards/STATUS.json`: Authorization Receipts -10,
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
- The revised package was resubmitted as `xxxx/110966` only after
  `npm run preprint:build`, `npm run check:preprint`, and `npm run test:preprint`
  passed and the editor-facing contribution was materially distinct from the
  rejected framing.
- The paper remains single-author: Iman Schrock, EMILIA Protocol, Inc. The
  external Rust verifier author remains an acknowledged external implementation
  party, not a co-author.
