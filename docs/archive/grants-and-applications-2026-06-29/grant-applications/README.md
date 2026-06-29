# Grant Applications — EMILIA Protocol (2026 Q2)

This directory contains grant / partnership program packages. Each subdirectory
has:

- `application.md` — the submission content, tailored to that program's format
- `submission.md` — exactly how to submit (URL, form fields, attachments, contact)
- Any supporting attachments referenced in the application

## Status tracker

| Program | Subdir | Status | Next action | Owner |
|---|---|---|---|---|
| NSF SBIR Phase I — Topic CT | [`nsf-sbir-phase-1/`](./nsf-sbir-phase-1/) | DRAFT | Submit Project Pitch at https://seedfund.nsf.gov | Iman |
| NIST AISI Consortium | [`nist-aisic/`](./nist-aisic/) | DRAFT | Email aiconsortium@nist.gov + sign CRADA | Iman |
| DARPA SAFE-AI BAA | [`darpa-safe-ai/`](./darpa-safe-ai/) | TEMPLATE | Watch SAM.gov for next AI-verification BAA | Iman |
| DHS S&T SBIR (FY26) | [`agency-sbir-dhs-nist/`](./agency-sbir-dhs-nist/) | WATCH | Monitor sbir2.st.dhs.gov + SAM.gov for FY26 topics (est. May–Jul 2026); pre-register SAM.gov | Iman |
| NIST SBIR (FY26) | [`agency-sbir-dhs-nist/`](./agency-sbir-dhs-nist/) | WATCH | Monitor nist.gov/oam/funding-opportunities + grants.gov for FY26 NOFO | Iman |
| AAIF Proposal v3 | [`aaif/`](./aaif/) | HOLD — IP TRANSFER | Do not submit EMILIA as-is; AAIF acceptance requires transfer of project trademarks/assets to LF | Iman |
| OpenAI Cybersecurity Grant | [`openai-cybersecurity/`](./openai-cybersecurity/) | DRAFT | Fill form at https://openai.com/form/cybersecurity-grant-program | Iman |
| Anthropic Research Grants | [`anthropic-research/`](./anthropic-research/) | DRAFT | Submit via Anthropic researcher access program | Iman |
| Emergent Ventures (EV AI) | [`emergent-ventures/`](./emergent-ventures/) | DRAFT — quorum-led | Apply (~30 min) at https://www.mercatus.org/emergent-ventures, note EV AI | Iman |
| SFF Speculation Grant | [`sff-speculation/`](./sff-speculation/) | DRAFT — quorum-led | Apply (rolling) at https://survivalandflourishing.fund/ → Speculation Grants; prereq for the S-Process round | Iman |

**Net-new since the two-person-rule (EP-QUORUM-v1) shipped 2026-06-20** — the
multi-party quorum is now the lead differentiator across applications. Standards
artifacts to cite/attach: `standards/draft-schrock-ep-quorum-00.md` (IETF
companion draft) and `docs/papers/ep-quorum-preprint.md` (arXiv preprint, cs.CR).
Fast new targets surfaced: **Emergent Ventures** and **SFF Speculation** (above);
also watch **NSF Safe-OSE 2026**, **Sovereign Tech Standards Network** (next
cohort — perfect IETF fit), and the **Frontier Model Forum AI Safety Fund**
Round 3 (submit research-interest form now). Note: Manifund and LTFF already
submitted (see SUBMISSION-PLAYBOOK.md) — for those, post a project *update*
citing the shipped quorum rather than re-applying.

## Recommended submission order

Lowest friction first — get the easy ones in the inbox before tackling the
heavyweights.

1. **AAIF technical outreach only** (15 min) — do not submit EMILIA as an AAIF project proposal unless counsel approves asset/trademark transfer; use informal TC/staff outreach or a future narrow neutral subproject instead.
2. **OpenAI Cybersecurity Grant** (30 min) — short web form, real money, fast review.
3. **Anthropic Research Grants** (30 min) — short form, formal-verification fit is excellent.
4. **NIST AISIC** (1 hr) — credibility play; CRADA paperwork takes longest.
5. **NSF SBIR Project Pitch** (2 hrs) — biggest dollar amount; needs care. Pitch first, full Phase I only if invited.
6. **DARPA SAFE-AI** (variable) — wait for the right BAA, then respond.

## Common attachments referenced across multiple programs

Already in the repo:

- `formal/PROOF_STATUS.md` — 26 TLA+ theorems verified (T1–T26)
- `formal/ep_handshake.tla` / `formal/ep_relations.als` — formal models
- `docs/conformance/RED_TEAM_CASES.md` — 85 adversarial test cases
- `docs/security/AUDIT_METHODOLOGY.md` — internal audit methodology
- `docs/compliance/NIST-AI-RMF-MAPPING.md` — 38 subcategories
- `docs/compliance/EU-AI-ACT-MAPPING.md` — Articles 9–15 + 26
- `docs/AAIF-PROPOSAL-v3.md` — refreshed v3.3 AAIF proposal
- `standards/draft-schrock-ep-authorization-receipts-01.md` — current authorization-receipt protocol draft
- `standards/draft-schrock-ep-enforcement-point-00.md` — Guard / enforcement-point profile
- `standards/draft-schrock-emilia-eye-00.md` — Emilia Eye advisory profile
- `PIPs/PIP-003-signoff.md` / `PIPs/PIP-004-commit.md` / `PIPs/PIP-005-eye.md` — Signoff, Commit, and Eye extensions
- `docs/RECEIPT-CLAIMS.md` — exact authorization-receipt claims and non-claims
- `docs/positioning/DIFFERENTIATION.md` — adjacent-work and category map
- `docs/conformance/FEDERATION-PROOF.md` — two-operator federation proof and open independent-operator milestone
- `packages/issue/README.md` — local issuance package and CLI
- `packages/verify/README.md` — offline verification package
- `packages/openai-guard/README.md` — OpenAI-compatible tool-call gating
- `packages/require-receipt/README.md` — demand-side receipt requirement middleware
- `docs/essays/why-authorization-is-not-proof.md` — authorization vs proof narrative
- `docs/essays/the-model-is-the-crumple-zone.md` — accountability narrative
- `docs/pilots/GOVGUARD-PILOT-OFFER.md` — observe-mode pilot wedge
- `docs/AWS-GRANT-APPLICATION.md` — historical AWS proposal (source for content reuse)
