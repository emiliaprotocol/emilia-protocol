# FLOSS/fund — Submission (EMILIA Protocol)

**Date:** 2026-06-13
**Applicant:** Iman Schrock, founder and sole maintainer, EMILIA Protocol, Inc.
**Status:** Submission-ready. The required `funding.json` manifest already exists at the repo root.

---

## What FLOSS/fund is

FLOSS/fund is a Zerodha-backed program that disburses **up to $1,000,000 per year** to free and open-source projects, in grants of **$10,000–$100,000** per recipient. It is **rolling and low-friction**, open to any entity worldwide (individual, group, or organisation, including for-profit), and has **no hard adoption gate** — projects of all sizes are eligible and are judged on merit rather than a numeric download/dependent threshold.

The mechanism is a machine-readable manifest, not a long-form application: you publish a **`funding.json`** file conforming to the **funding-manifest v1.0.0** schema (the open `funding.json` standard, documented at fundingjson dot org), host it at a public URL, and submit that URL at FLOSS/fund. A reviewer evaluates the project from the manifest and its public artifacts.

This program **stacks with the GitHub Secure Open Source Fund** (see `../github-secure-oss-fund/SUBMISSION.md`). File both. The GitHub fund is the #1 target; FLOSS/fund is the lowest-friction #2.

---

## The manifest (already written)

A valid `funding.json` conforming to funding-manifest **v1.0.0** is at the **repository root**:

`/funding.json` → https://github.com/emiliaprotocol/emilia-protocol/blob/main/funding.json

It was validated against the published schema (the `floss-fund/go-funding-json` v1 models and validator):

- `entity.type: "organisation"`, `entity.role: "owner"` (both in the allowed enum sets).
- One project, `guid: "emilia-protocol"`, `licenses: ["spdx:Apache-2.0"]` (Apache-2.0 is a valid SPDX id), 8 tags (within the 1–10 limit; each matches the required lowercase `^[a-z0-9]+(?:-[a-z0-9]+)*$` tag pattern).
- One funding channel (`type: "other"`) and two plans (`status: "active"`; `frequency` of `one-time` and `monthly`; `currency: "USD"`), each referencing the channel id. `history` is an empty array (allowed).
- All guids match the required id pattern; all descriptions are within length limits; `entity.phone` is left empty (allowed — only validated when non-empty).

### Important — funding channel / payout prerequisite

The manifest's single funding channel currently points its `address` at the **repository URL**, not a live payout link, because **GitHub Sponsors is not yet enabled for the `emiliaprotocol` organization**. We deliberately did not put a sponsors URL that implies funds can be received before that page exists.

**Before relying on this for payout you must:**

1. **Enable GitHub Sponsors** for the `emiliaprotocol` organization (this is also the payout rail for the GitHub Secure Open Source Fund, so it is a one-time setup that serves both programs).
2. **Update `funding.json`** — change the channel `address` from the repository URL to `https://github.com/sponsors/emiliaprotocol` and trim the "pending enablement" note from the channel description.
3. Re-validate (see below) and re-host the updated manifest.

Until then the manifest is schema-valid and submittable, and the channel description tells reviewers to contact `team@emiliaprotocol.ai` to arrange funding.

---

## Exact steps to submit

1. **`funding.json` is at the repo root** (done). On push, it is reachable at a stable raw URL on GitHub's `raw.githubusercontent.com` host, path `/emiliaprotocol/emilia-protocol/main/funding.json` (or the rendered view at `https://github.com/emiliaprotocol/emilia-protocol/blob/main/funding.json`). Either a repo-root URL, a `.well-known` path, or the project site is an acceptable host; the repo root is simplest. Confirm the raw URL resolves publicly after pushing.
2. **Validate the manifest** with FLOSS/fund's validator at **https://dir.floss.fund/validate** — paste the public manifest URL and confirm it reports no schema errors. (It was already validated against the v1 schema offline; the online validator is the final check.)
3. **Submit the manifest URL** at **https://dir.floss.fund/submit**. Provide the public `funding.json` URL from step 1. The program reads the project, entity, and funding details directly from the manifest.
4. **Prerequisite reminder — GitHub Sponsors must be enabled to actually receive funds.** Complete the channel update in the section above so an approved grant has a live destination.

---

## Quick reference

| Item | Value |
|---|---|
| Manifest schema | funding-manifest **v1.0.0** |
| Manifest location | repo root: `/funding.json` |
| Raw URL (after push) | `raw.githubusercontent.com` host, path `/emiliaprotocol/emilia-protocol/main/funding.json` |
| Validator | https://dir.floss.fund/validate |
| Submit | https://dir.floss.fund/submit |
| Award range | $10,000–$100,000 (≤ $1M/yr pool) |
| Adoption gate | None (merit-based) |
| Payout prerequisite | Enable GitHub Sponsors for `emiliaprotocol`, then update channel address |
| Stacks with | GitHub Secure Open Source Fund |
