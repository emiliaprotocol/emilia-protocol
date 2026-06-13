# AAIF — Submission Package (channel-corrected June 2026)

**The intake is NOT an email.** AAIF (Agentic AI Foundation, Linux Foundation) takes
project proposals through a GitHub issue form, reviewed by the Technical Committee
(>50% vote + Governing Board). Verified June 2026:

- **Submit here:** <https://github.com/aaif/project-proposals/issues/new?template=project-proposal.yml>
- Lifecycle policy: <https://github.com/aaif/project-proposals/blob/main/governance/project-lifecycle-policy.md>
- How-to: <https://aaif.io/blog/how-to-submit-your-project-to-the-aaif/>
- **Working-group signup (do this first):** the Google Form linked from the how-to page
  ("join working groups") — WG participation is where TC sponsors are found.

## Strategy (read before clicking submit)

AAIF's lowest entry rung is **Growth**, which requires a **TC sponsor**, a growth
plan toward diverse maintainership, and evidence of successful production use at
wide scale. EP does not clear all of that today, and a premature proposal would
create a public review trail before the strongest sponsor and pilot evidence is
ready.

Recommended sequence:
1. **Join the working group now** (form above). Engage for 2-4 weeks; EP's receipts
   thesis is directly relevant to MCP security/agent-accountability conversations.
2. **Find the TC sponsor** through that engagement — it is a literal entry requirement.
3. **Submit the formal proposal** when (a) a sponsor is named and (b) the GovGuard
   county pilot provides the production-use evidence. Target: Q3-Q4 2026.

If you want to submit immediately anyway, the proposal is honest about the gaps
(Maturity section maps each Growth criterion to status + plan), which is the best
possible posture for an early submission — but the sponsor-first path converts better.

## Pre-submission checklist

- [x] `@emilia-protocol/verify` **1.4.0** and `@emilia-protocol/issue` **0.2.0**
      published to npm (verified 2026-06-13)
- [x] Datatracker -01 **confirmed** (verified 2026-06-13)
- [ ] PDF regenerated: `pandoc docs/AAIF-PROPOSAL-v3.md -o aaif-proposal-v3.pdf`

## Issue-form body (paste-ready)

Use `docs/AAIF-PROPOSAL-v3.md` content mapped to the form fields. Short-answer
versions for the usual fields:

- **Project name:** EMILIA Protocol (EP) — authorization receipts
- **License:** Apache-2.0
- **Repository:** https://github.com/emiliaprotocol/emilia-protocol
- **One-sentence description:** Open standard and Apache-2.0 reference implementation
  for authorization receipts: named-human, device-bound signoff over exact
  irreversible agent actions, verifiable offline by anyone.
- **Why AAIF / ecosystem value:** AAIF governs how agents connect (MCP), execute
  (goose), and are guided (AGENTS.md). None of those produce portable evidence that
  a named human authorized a specific irreversible action. EP is that missing
  artifact, and no single vendor should own it. Decision logs are testimony;
  receipts are evidence.
- **Maturity / adoption:** see the proposal's "Maturity, Honestly" table — single-org
  maintainership today, IETF I-D at -01, three-language verifiers, formal models
  (26 TLA+ properties, 22 Alloy assertions), 60-day government observe-mode pilot
  as the first production wedge.
- **Roadmap:** see the proposal's 6-12 Month Roadmap table.
- **Sponsor:** [name the TC sponsor here — required; do not submit "TBD"]
- **Contact:** Iman Schrock, team@emiliaprotocol.ai

## Optional human-contact email (for WG members / staff you meet, NOT an intake)

Subject: EMILIA Protocol — authorization receipts for irreversible AI-agent actions

> Hello —
>
> I maintain EMILIA Protocol, an open (Apache-2.0) standard for authorization
> receipts: a named human's device-bound signoff over an exact irreversible agent
> action, verifiable offline by anyone. IETF I-D draft-schrock-ep-authorization-receipts
> is at -01, with verifiers in JS/Python/Go and a zero-dependency local issuer
> (npx @emilia-protocol/issue demo shows the whole loop in 60 seconds).
>
> AAIF's projects cover how agents connect, execute, and are guided; EP covers how
> their irreversible actions get provably authorized. I'd value a conversation about
> whether this belongs in the foundation — and what the Technical Committee would
> want to see first. Proposal attached.
>
> Iman Schrock · team@emiliaprotocol.ai · emiliaprotocol.ai

Attach: `aaif-proposal-v3.pdf` (and nothing else — the proposal links the rest).
