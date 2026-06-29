# NIST AI Consortium — Submission Instructions

<!--
VERIFIED JUNE 2026. The program formerly called AISIC is now the
"NIST Artificial Intelligence Consortium," reopened for new members on
May 29, 2026 (Fed. Reg. 2026-10779). The submission email is UNCHANGED
(aiconsortium@nist.gov) and the CRADA is still the join mechanism. The
old "working groups" are now six published TASK GROUPS. Sources are
listed at the bottom of application.md.
-->

## Step 1 — Send the letter of interest

**To:** `aiconsortium@nist.gov`
(or the official webform linked from
https://www.nist.gov/artificial-intelligence/nist-ai-consortium/submit-letter-interest-join-nist-ai-consortium ;
hardcopy also accepted at NIST, 100 Bureau Drive, Mail Stop 8900,
Gaithersburg, MD 20899.)

**Subject:** NIST AI Consortium — Letter of Interest — EMILIA Protocol
(open authorization-receipt evidence for AI agents)

**Body:** paste the "Letter of interest" section of `application.md`
verbatim. The Federal Register notice requires the letter to state, at
minimum:

1. the role(s) the organization will play in the consortium efforts;
2. the specific expertise it intends to bring;
3. the products, services, data, or other technical capabilities it
   will use in consortium activities;

plus the organization's address and point of contact. The current
`application.md` letter is written to cover all three. **Do not include
proprietary information** — the notice prohibits it.

Keep it to one page. Lead with the two load-bearing facts: the IETF
draft is at -01, and the protocol carries machine-checked safety
(26 TLA+ properties, 22 Alloy assertions, 0 errors/counterexamples,
all in CI).

## Step 2 — CRADA

Selection is first-come, first-served on complete letters. When NIST
selects EP, they send the consortium CRADA template. Standard posture:

- Apache-2.0 work product is fully compatible.
- IP retention by EP for protocol-specification work; non-exclusive
  license to NIST for any NIST-funded extensions.
- Public attribution permitted and expected for consortium artifacts.

The first review period begins June 2026, then roughly biannually. There
is no hard deadline for THIS letter — earlier is better because review
is first-come, first-served.

## Step 3 — Task-group participation

Membership lands you in the consortium's six task groups (these replaced
the old "working group" framing):

- **AI TEVV** (Testing, Evaluation, Verification & Validation) Zero Draft
- AI Evaluation and Measurement Methods
- AI Documentation Cards
- Annotation for AI Risks & Validity
- BENGAL (Bias Effects & Notable Generative AI Limitations)
- Chemical and Biological Security

Recommend going deep in **AI TEVV** + **AI Evaluation and Measurement
Methods**, with the RMF mapping offered to **AI Documentation Cards**.
EP's receipt is a natural fit for TEVV: it is a verifiable artifact that
an evaluator can produce and an independent party can check.

## What to do BEFORE sending

- [ ] Confirm the latest submission webform URL on the NIST page above
      (the email `aiconsortium@nist.gov` is verified current as of
      June 2026, but NIST may prefer the webform).
- [ ] Confirm `@emilia-protocol/verify` 1.4.0 and
      `@emilia-protocol/issue` 0.2.0 are live on npm (the letter cites
      them).
- [ ] Confirm `draft-schrock-ep-authorization-receipts-01` is posted on
      the IETF datatracker (the letter cites -01).
- [ ] Confirm github.com/emiliaprotocol/emilia-protocol is publicly accessible without
      auth.
- [ ] Confirm no proprietary content slipped into the letter.

## Why this is worth doing

Consortium membership is a credibility surface: a NIST-acknowledged
contribution improves the read on every other submission (SBIR, AAIF,
foundation grants). The cost is one CRADA and modest task-group time;
the asymmetry is favorable. EP's specific edge is that it brings the one
thing the measurement program is short on — a concrete, open, verifiable
artifact — rather than another framework opinion.

## Timeline

- LOI sent -> NIST acknowledgment: typically 1–2 weeks
- Selection (first-come, first-served): within the June 2026 review
  window, then biannually
- CRADA negotiation: 4–8 weeks
- Task-group onboarding: 1–2 weeks after CRADA signed
