# arXiv staging: Authorization Receipts preprint

**Status: READY to submit. NOTHING has been submitted.** This directory is a
prepared arXiv source package. Submission is the lead's call (account login,
author metadata, the actual upload).

## What is in this directory

| File | What it is | State |
|---|---|---|
| `main.tex` | Full LaTeX source, faithful carriage of `papers/authorization-receipts-preprint.md` at HEAD | Built |
| `main.pdf` | Compiled PDF, 22 pages, from `main.tex` | Built with `tectonic` (see below) |
| `STAGING.md` | This checklist | — |

## PDF build — actually run this session

Built with **`tectonic` 0.x** (the only LaTeX engine available on this machine;
no `pdflatex`/`xelatex`/MacTeX installed). Command run in `papers/arxiv/`:

```
tectonic main.tex
```

Output: `main.pdf`, 22 pages, ~123 KiB. Clean build. One residual 20.06pt
overfull `\hbox` (a hyphenated compound word in Section 3.2 prose) — cosmetic,
well inside normal typesetting tolerance, and irrelevant to arXiv's own
pdflatex/latexmk pipeline. No errors.

**arXiv note on the engine:** arXiv builds submitted `.tex` itself with its own
TeX Live (pdflatex/latexmk), it does not run tectonic. `main.tex` uses only
stock packages present in TeX Live (`geometry`, `amsmath`, `amssymb`,
`textcomp`, `microtype`, `enumitem`, `fancyvrb`, `parskip`, `hyperref`, `xurl`,
`seqsplit`, `lmodern`), so it should build unchanged on arXiv. The lead should
still do one local `latexmk -pdf main.tex` before upload if a TeX Live install
is handy, to confirm against the exact engine arXiv uses.

## Every quantitative claim traces to a repo artifact (no invented numbers)

| Claim in paper | Value | Repo source read this session |
|---|---|---|
| Conformance suites / vectors | 18 / 251 | `conformance/conformance-manifest.json` → `totals.suites=18`, `totals.vectors=251`; also sums to 251 across the 18 suite entries. `manifest_sha256 = 1285c269b3d58e325c2432d59a95e598761abf3cf3c8f2933b82f21b59214888` |
| Tamarin core lemma block (5 lines) | verbatim | `formal/PROOF_STATUS.md` (matches byte-for-byte) |
| Tamarin quorum lemma block (5 lines) | verbatim | `formal/PROOF_STATUS.md` |
| Tamarin composed lemma block (12 lines) | verbatim | `formal/PROOF_STATUS.md` |
| Ten strict composed lemmas verified; 2 deliberate falsifications | 10 / 2 | `formal/PROOF_STATUS.md` ("10 strict lemmas verified; ... comparisons falsified"); `lib/proof-stats.json` `tamarin.verifiedObligations=10`, `deliberatelyUnsafeCounterexamples=2` |
| TLA+ states / distinct / invariants | 413,137 / 45,342 / 26 | `formal/PROOF_STATUS.md`; `lib/proof-stats.json` `tla.invariants=26` |
| Alloy assertions | 15 + 7 = 22 | `formal/PROOF_STATUS.md`; `lib/proof-stats.json` `alloy.assertions=22` |
| Rust external verifier commit / tree | `7faba360…` / `0553c5fa…` | `conformance/external/rust-cleanroom-jdieselny.v1.json` |
| Rust clean-room bundle / hostility | 16-suite / 164-vector; 353 + 6 | `conformance/external/rust-cleanroom-jdieselny.v1.json`; `lib/proof-stats.json` `externalImplementation.vectors=164`, `hostilityCases=359` |
| External reproduction (COSA / J Diesel NY) | 158 vectors | carried from preprint; matches EP-EXTERNAL-VERIFICATION-STATEMENT record |

### KNOWN COUNT DISCREPANCY — for the lead

`lib/proof-stats.json` currently reports `conformance.vectors = 232`, which is
**stale** relative to the authoritative `conformance/conformance-manifest.json`
(`totals.vectors = 251`, and the 18 suite entries sum to 251). The paper uses
**251**, matching the manifest and the source preprint. I did **not** edit
`lib/proof-stats.json` (shared count file, out of my scope). Flagging so the lead
can re-sync proof-stats to the manifest on merge. This is the only number where
the two repo sources disagree; every other figure is consistent across
proof-stats, PROOF_STATUS.md, and the manifests.

## Overclaim discipline verified (the paper does NOT do any of these)

- **VERIFIED vs ACCEPTED** kept separate: B3 in Section 5; "verified/accepted
  distinction" in Section 6.4. Not conflated anywhere.
- **Reproduction vs independent implementation**: Section 8 states the JS/Python/Go
  ports are "same-team ports … not three independent implementations"; the COSA
  statement is "historical reproduction result"; the Rust verifier is
  "external interoperability and parser-robustness evidence" and
  "EP-CONFORMANCE-CASE-v1 structurally reports zero strict independently attested
  clean-room acceptances." No independence upgrade.
- **No "IETF-adopted"**: the Internet-Drafts are described as "individual
  submissions with no working-group status" and "work in progress." No adoption
  or endorsement claimed.
- **fail-closed** used only as refuse-with-reason (B4, Section 6.3), never as
  "throws/crashes."
- Symbolic scope exclusions stated exactly (Section 7.4): WebAuthn internals,
  directory/log mechanics, arbitrary k-of-n, collusion/coercion, canonicalization,
  amount arithmetic, policy authorship, clock freshness, computational security,
  downstream effects.

## arXiv submission checklist (for the lead — DO NOT auto-run)

1. **Account**: log in at arxiv.org (or register). New submitters may need an
   endorsement for cs.CR; check whether the account is already endorsed.
2. **Primary category**: `cs.CR` (Cryptography and Security).
   **Suggested cross-list**: `cs.CY` (Computers and Society). (Matches the sibling
   `docs/papers/ep-multi-handshake-arxiv.tex` header convention in this repo.)
3. **License**: source header declares `CC-BY-4.0`. Select the matching arXiv
   license (**CC BY 4.0**) in the submission form. If a different license is
   wanted, change the SPDX header in `main.tex` first so they agree.
4. **Upload**: submit `main.tex` alone (self-contained, no external figures/bib
   files — bibliography is an inline `thebibliography`). arXiv will compile it.
   Optionally upload `main.pdf` is NOT how arXiv works — it builds from source;
   do not upload the PDF as the submission, upload the `.tex`.
5. **Title / abstract**: copy from `main.tex` (`\title{...}` and the `abstract`
   environment). The abstract has no TeX macros, so it pastes cleanly into the
   arXiv abstract box.
6. **Metadata NEEDING THE LEAD**:
   - **Author list**: currently single author "Iman Schrock, EMILIA Protocol, Inc."
     Confirm whether any co-authors (e.g. contributors named in the paper —
     J Diesel NY authored the external Rust verifier but is credited as an
     external party, not necessarily a co-author) should be added. Left as-is
     pending the lead's call.
   - **ORCID**: not embedded. Add the lead's ORCID in the arXiv author form.
   - **Comments field** (optional): e.g. "22 pages. Reference implementation,
     Tamarin/TLA+/Alloy models, and conformance vectors available under Apache-2.0."
   - **ACM class / MSC** (optional): none set; can be left blank.
7. **Report-nr / journal-ref**: none. Leave blank (this is a preprint).
8. **Do a local `latexmk -pdf main.tex`** against TeX Live before final submit if
   available, to confirm the exact engine arXiv uses (see build note above).

## What was NOT done (honest boundaries)

- **Nothing submitted.** No arXiv account touched, no upload, no email.
- `lib/proof-stats.json` not edited (stale 232 flagged above for the lead).
- No co-author list, ORCID, or license *decision* made — those are the lead's.
- PDF built with `tectonic`, not the arXiv pdflatex/latexmk toolchain (not
  installed here). Package set is TeX Live-standard, so this is expected to be a
  no-op difference, but it is unverified against arXiv's exact engine.
