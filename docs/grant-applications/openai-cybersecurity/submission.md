# OpenAI Cybersecurity Grant — Submission Instructions

**Form URL**: https://openai.com/form/cybersecurity-grant-program/
(verified live, June 2026 — appears in OpenAI's own program index and
search results. If it 404s, search "OpenAI cybersecurity grant program
application" and follow the openai.com/form link.)

**Index/context page**: https://openai.com/index/openai-cybersecurity-grant-program/

**Cost**: Free
**Award**: Increments of $10,000 USD — API credits, direct funding, and/or
equivalents
**Cycle**: Rolling review (no longer quarterly). OpenAI evaluates proposals
as they arrive and contacts promising teams even when immediate funding
isn't possible.

> Program context (verified June 2026): On Feb 5, 2026 the program evolved
> toward large-scale deployment of models for cyber defense, added $10M in
> API credits, and launched Trusted Access for Cyber. Current priorities:
> defensive cybersecurity *agents*, secure-by-design software, threat
> intelligence, porting to memory-safe languages, and open-source software
> defense. Recent recipients include Socket, Semgrep, and Trail of Bits.
> Offensive-security projects are not funded.

## Steps

1. Go to https://openai.com/form/cybersecurity-grant-program/
2. Sign in with `team@emiliaprotocol.ai` if prompted
3. Fill the web form fields, pasting from `application.md`:
   - Project name → section 1
   - One-line description → section 2
   - Problem statement → section 3
   - Approach / solution → section 4
   - Why a fit for OpenAI's program → section 5
   - Use of funds / budget → section 6
   - Team → section 7
   - Links / public artifacts → section 8
4. Submit.

Because review is rolling, there is no cutoff to wait for — submit when the
public artifacts below are live.

## What to attach if the form supports uploads

- The IETF Internet-Draft `draft-schrock-ep-authorization-receipts-01`
  (PDF/txt) — proof the protocol is standardized, not just shipped.
- `formal/PROOF_STATUS.md` — proof of the formal-verification claims.

If the form doesn't accept attachments, link them as raw GitHub / IETF
datatracker URLs in section 8. Reviewers do follow public-artifact links.

## What to expect post-submission

- Auto-acknowledgement email (historically within ~24h)
- If promising: OpenAI reaches out for a short interview / call
- Support delivered as API credits and/or direct funding in $10K increments

## What to do BEFORE submitting

The program prioritizes projects already shipping and useful to defenders.
Make sure these are public on the day you submit:

- [x] `@emilia-protocol/verify` 1.4.0 and `@emilia-protocol/issue` 0.2.0 on npm
- [x] IETF Internet-Draft draft-schrock-ep-authorization-receipts-01 posted
- [x] Live device-bound approval demo at emiliaprotocol.ai/try
- [x] MCP server integration documented (the agentic-defense hook)
- [x] Public GitHub with active commits in the last 30 days
- [ ] One named external reference / advisor — not required, but strengthens
  the application. Worth a 30-min ask to a NIST AISI contact or AI-safety /
  security researcher willing to be named.

## Positioning reminders (honesty)

- No customers. Pilots are in outreach (e.g. GovGuard county
  payment-integrity package) — say "in outreach," not "deployed."
- Say "irreversible action," not "consequential."
- The receipt proves authorization — never "EMILIA proves." The runtime
  issues; the receipt is what a defender verifies, offline.
