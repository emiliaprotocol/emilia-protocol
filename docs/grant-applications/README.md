# Grant Applications — EMILIA Protocol (2026 Q2)

This directory contains application packages for six grant / partnership
programs. Each subdirectory has:

- `application.md` — the submission content, tailored to that program's format
- `submission.md` — exactly how to submit (URL, form fields, attachments, contact)
- Any supporting attachments referenced in the application

## Status tracker

| Program | Subdir | Status | Next action | Owner |
|---|---|---|---|---|
| NSF SBIR Phase I — Topic CT | [`nsf-sbir-phase-1/`](./nsf-sbir-phase-1/) | DRAFT | Submit Project Pitch at https://seedfund.nsf.gov | Iman |
| NIST AISI Consortium | [`nist-aisic/`](./nist-aisic/) | DRAFT | Email aiconsortium@nist.gov + sign CRADA | Iman |
| DARPA SAFE-AI BAA | [`darpa-safe-ai/`](./darpa-safe-ai/) | TEMPLATE | Watch SAM.gov for next AI-verification BAA | Iman |
| AAIF Proposal v3 | [`aaif/`](./aaif/) | READY | Send cover email + `docs/AAIF-PROPOSAL-v3.md` | Iman |
| OpenAI Cybersecurity Grant | [`openai-cybersecurity/`](./openai-cybersecurity/) | DRAFT | Fill form at https://openai.com/form/cybersecurity-grant-program | Iman |
| Anthropic Research Grants | [`anthropic-research/`](./anthropic-research/) | DRAFT | Submit via Anthropic researcher access program | Iman |

## Recommended submission order

Lowest friction first — get the easy ones in the inbox before tackling the
heavyweights.

1. **AAIF v3** (10 min) — already drafted, just send.
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
- `docs/AAIF-PROPOSAL-v3.md` — the v3 AAIF proposal
- `docs/AWS-GRANT-APPLICATION.md` — historical AWS proposal (source for content reuse)
