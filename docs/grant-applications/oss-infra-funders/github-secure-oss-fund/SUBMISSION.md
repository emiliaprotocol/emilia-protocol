# GitHub Secure Open Source Fund — Submission (EMILIA Protocol)

**Date:** 2026-06-13
**Applicant:** Iman Schrock, founder and sole maintainer, EMILIA Protocol, Inc.
**Status:** Submission-ready. Fill each field below into the application form.

---

## Program at a glance

- **Program:** GitHub Secure Open Source Fund
- **Program page:** https://github.com/open-source/github-secure-open-source-fund
- **Announcement:** https://github.blog/news-insights/company-news/announcing-github-secure-open-source-fund/
- **Award structure:** $10,000 per project paid via GitHub Sponsors, split **$6k during the program, $2k at the 6-month check-in, $2k at the 12-month check-in** — plus the security-education cohort, dedicated **GitHub Security Lab** time, tool access (**CodeQL, Copilot, AutoFix**), and **$10k Azure credits**.
- **Commitment:** ~15 hours over 3 weeks, plus two ~2.5-hour check-ins (6-month, 12-month).
- **Cadence:** Rolling. One application is considered for all upcoming sessions.
- **Eligibility relevant to us:** open to individual maintainers and small teams; for-profit-backed maintainers are permitted; only current GitHub employees are excluded. No published download/dependent threshold.

---

## Application — field by field

### Project name

EMILIA Protocol — authorization-receipt verifiers and conformance suite

### Repository URL

https://github.com/emiliaprotocol/emilia-protocol

### License

Apache-2.0

### One-sentence description

An open standard and zero-dependency reference toolkit that produces an **authorization receipt** — offline-verifiable proof that a named human approved an exact, irreversible AI-agent action before it executed — with interoperable verifiers in JavaScript, Python, and Go and an adversarial conformance suite.

### What the project is, and why it is security-relevant

AI agents are moving from recommending actions to taking them: deploying code, moving money, rotating credentials, calling tools with real-world effect. The defensive gap is no longer "is the model accurate?" but "did this agent have authorization to take *this specific irreversible action* on behalf of *this specific principal* — and can a defender prove it afterward, offline, without trusting the system whose conduct is in question?"

EP closes that gap with a small, formally specified artifact. A verified authorization **receipt** proves — with mathematics, by anyone, with no call back to any EP operator — that a specific enrolled key produced a user-verified signature over the exact action (change the amount, beneficiary, or target and the receipt no longer verifies), under a hash-pinned policy, consumed at most once, in an append-only log. The **receipt** is the thing that proves this; the runtime does not vouch. And the *absence* of a receipt for a gated action is itself evidence of bypass — defenders get a positive signal, not just a missing log line.

The fundable open surface is the verification toolchain that makes the receipt *checkable by third parties*:

- **`@emilia-protocol/verify` 1.4.0** and **`@emilia-protocol/issue` 0.2.0** — zero-dependency npm packages (verify anywhere; issue locally).
- **Three independent reference verifiers** (JavaScript, Python, Go) proven to agree on the canonical adversarial conformance vectors on every push — the IETF bar of multiple interoperable implementations.
- **A conformance suite** plus **85 cataloged red-team cases**.
- **Formal verification:** 26 TLA+ safety properties (413,137 states explored) and 22 Alloy assertions (15 core + 7 federation), 0 counterexamples, re-run in CI.
- **IETF Internet-Draft** `draft-schrock-ep-authorization-receipts-01` (including PIP-007, an initiator-escalation attestation).
- An **MCP server** so any MCP-speaking agent can place EP as a pre-action guard without changing its tool definitions.

This is open security infrastructure: the value to the ecosystem is a verifier any defender can run, independent of the operator under examination.

### Adoption and project stage (stated plainly)

EP is young. `@emilia-protocol/verify` is at **~210 downloads/week (week of 2026-06-11)**; a first pilot is in outreach; **there are no production customers yet**. What exists today is the *standard and its verifiable implementation*: the Internet-Draft, three interoperable verifiers, the conformance suite, the formal models, and the zero-dependency packages — all public and reproducible. We are applying to harden that public-good security toolchain at the stage where hardening is cheapest and most durable: before adoption, rather than after an incident forces it.

### Backing and governance

EP is maintained by Iman Schrock and backed by **EMILIA Protocol, Inc., a Delaware C-corp**. The fund permits for-profit-backed maintainers, and we state the backing plainly. The **protocol, the three verifiers, the conformance suite, the formal models, and the npm packages are Apache-2.0 and will remain open**; managed policy, orchestration, and sector packs are optional product surfaces built on top, not part of the open core. Governance, contribution, and security-disclosure processes are public: `GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and DCO sign-off (`DCO.md`). This application concerns only the open security toolchain.

### Security work we would do in the cohort

All milestones are security *hardening* of the open toolchain — not features:

1. **Cross-language verifier hardening.** Differential and property-based testing across the JavaScript, Python, and Go verifiers to prove byte-exact agreement on canonicalization, signature verification, and rejection paths; eliminate any divergence a forged receipt could exploit. (CodeQL + AutoFix applied across all three.)
2. **Supply-chain hardening of the zero-dependency packages.** Pinned provenance and SBOM verification for `@emilia-protocol/verify` and `@emilia-protocol/issue`, signed releases, and a reproducible-build check — so a verifier a defender installs is exactly the audited source.
3. **Conformance-suite and red-team expansion.** Extend the conformance vectors and the 85-case red-team catalog to cover the full PIP-007 escalation-attestation path and the WebAuthn challenge-binding edge cases, and publish them so any third party can validate independently.
4. **Fuzzing the parse/verify boundary.** Structured fuzzing of receipt parsing and signature verification across all three languages to surface memory-safety and malformed-input issues before adoption.

We would use the GitHub Security Lab time and CodeQL/AutoFix tooling directly against the verifiers, and the Azure credits to run the cross-language differential and fuzzing harnesses in CI.

### What an honest receipt does and does not prove

So the reviewer can calibrate: a receipt proves a named human approved this exact action under the stated policy, consumed once, verifiable offline. It does **not** prove the decision was wise, that the policy was adequate, that the approver was not coerced or colluding, or that the signing surface rendered the action faithfully — those are policy, presentation, and human factors outside the signature's reach. EP's credibility depends on never claiming more than the cryptography delivers; the full claims-and-non-claims statement is at `docs/RECEIPT-CLAIMS.md`.

### Maintainer bio

**Iman Schrock**, founder and sole maintainer (ORCID 0009-0004-0290-5433). Authored the protocol stack: the IETF Internet-Draft (`draft-schrock-ep-authorization-receipts-01`), 26 TLA+ properties and 22 Alloy assertions (0 counterexamples, re-run in CI), the 85-case red-team suite, the three-language verifiers, and the npm toolkit. Apache-2.0 history is public at github.com/emiliaprotocol/emilia-protocol. Contact: team@emiliaprotocol.ai.

### Public artifacts

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- IETF Internet-Draft: `draft-schrock-ep-authorization-receipts-01`
- npm: `@emilia-protocol/verify` 1.4.0, `@emilia-protocol/issue` 0.2.0
- Verify a receipt in your browser: https://www.emiliaprotocol.ai/verify
- Conformance: `CONFORMANCE.md`, `conformance/`
- Formal proofs: `formal/PROOF_STATUS.md`
- Threat model: `THREAT_MODEL.md`
- Receipt claims and non-claims: `docs/RECEIPT-CLAIMS.md`
- Essays: https://www.emiliaprotocol.ai/essays (start with "The Model Is the Crumple Zone")

---

## How to submit

1. **Open the application form** linked from the program page: https://github.com/open-source/github-secure-open-source-fund. The fund is rolling — a single application is considered for all upcoming sessions, so submit now.
2. **Have ready:** the field answers above (project name, repo URL, license, one-line and long descriptions, adoption/stage statement, backing/governance, the four hardening milestones, the claims/non-claims paragraph, maintainer bio, and the public-artifact links).
3. **Prerequisite — GitHub Sponsors must be enabled to receive the payout.** The $10k award is paid through GitHub Sponsors. **Enable GitHub Sponsors for the `emiliaprotocol` organization before (or immediately after) submitting** so the payout has a destination; without it, an award cannot be disbursed. This is the same prerequisite as the FLOSS/fund channel — set it up once and update both.
4. **Stacking:** This application stacks with the FLOSS/fund submission (see `../floss-fund/SUBMISSION.md`). File both; the GitHub fund is the #1 target and FLOSS/fund is the low-friction #2.
