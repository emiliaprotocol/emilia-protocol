# Anthropic Research / Grant — Submission Instructions

Verified June 2026. The draft's original three programs have shifted; the
programs below are the ones that actually exist now. Do them in this order.

## Path 1 — External Researcher Access Program (DO THIS FIRST)

The highest-fit, lowest-friction path: free Claude API credits for AI
safety & alignment research.

- **What it grants**: ~$1,000 in Claude API credits per approved applicant
  (higher in rare cases). API usage only, not the Claude web app.
- **Cadence**: reviewed the **first Monday of each month**. No individual
  feedback on rejections; reapplication with updated info is welcome.
- **Apply**: https://forms.gle/pZYC8f6qYqSKvRWn9
  (canonical link is in support.claude.com article 9125743,
  "What is the External Researcher Access Program?")
- **Content**: use sections 1, 3, 4, 5, 6 from `application.md`. Lead the
  free-text research-topic field with the crumple-zone thesis (section 2)
  + PIP-007 (section 3b) — that is the sharpest hook for a safety reviewer.

## Path 2 — Anthropic Fellows Program

4-month mentored AI-safety research with Anthropic scientists. ~$3,850/wk
stipend + ~$15k/mo compute. Listed areas include **AI control** and **AI
security** — PIP-007 agent-accountability + the formal control properties
fit squarely.

- **Cohorts**: May & July 2026; rolling for late-Sept 2026 and beyond.
- **Apply**: Anthropic careers (greenhouse job board) or fellows@anthropic.com.
- **Eligibility caveat**: requires residence + work authorization in
  US / UK / Canada (no visa sponsorship). Confirm this fits before
  investing in the application.
- **Content**: substantive written responses on motivation, research
  interest, fit, plus resume, optional code/publications, and three
  references. Pull the research framing from sections 2–3; the references
  ask is real — line up three before applying.

## Path 3 — Economic Futures Research Awards (secondary, optional)

$10K–$50K for empirical research on AI's economic impact. Only worth it if
you frame EP around the *economic externality* of unattributable agent
actions (liability, insurability, the cost of "the model did it"). Weaker
fit than Paths 1–2; pursue only if you want a labor/economics angle.
https://www.anthropic.com/economic-futures/program

## Path 4 — Direct researcher outreach (parallel, anytime)

Independent of the funded programs, getting EP onto the radar of
Anthropic's safety / control researchers unlocks every future program.

Subject:
> Verifiable authorization receipts for agent actions — crumple-zone
> protection for the model provider (formal proofs + IETF I-D)

Body: paste sections 2 and 3 from `application.md` (thesis + "why for
Anthropic"). Lead with the crumple-zone framing: receipts protect the
*model provider* from absorbing blame for human-authorized actions — cf.
the Nov 2025 espionage disclosure where the Senate letter went to
Anthropic. Attach `application.md` as PDF and the IETF I-D.

Target the right inbox: skip generic boxes when you can. Find the lead
author of a recent Anthropic paper on agent safety / AI control / agentic
misuse and write to them — researchers engage with work they can cite.

## What to do this week

1. Submit Path 1 (External Researcher Access) — aim for before the next
   first-Monday review.
2. Send one Path 4 outreach email to a named safety/control researcher.
3. Decide on Path 2 (Fellows) only if the US/UK/Canada residency works.

## Pre-flight checks before sending

- [x] EP repo public; README states the formal-verification + IETF-I-D claims
- [x] `@emilia-protocol/verify` 1.4.0 + `@emilia-protocol/issue` 0.2.0 on npm
      (proves the protocol is reified, not just a paper)
- [x] IETF I-D draft-schrock-ep-authorization-receipts-01 posted (incl. PIP-007)
- [x] "The Model Is the Crumple Zone" essay live at emiliaprotocol.ai/essays
      — link it; it *is* the pitch
- [ ] Three references lined up (only needed for Path 2 Fellows)
- [ ] PDF of `application.md` ready (`pandoc application.md -o ep-anthropic.pdf`)

## Positioning reminders (honesty)

- No customers. Pilots in outreach (GovGuard county payment-integrity
  package) — "in outreach," not "deployed."
- "Irreversible action," not "consequential."
- The receipt proves authorization — never "EMILIA proves." The runtime
  issues; the receipt is what gets verified, by anyone, offline.
