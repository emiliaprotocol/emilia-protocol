# Anthropic Research / Grant — Submission Instructions

Anthropic's research-funding programs are not as standardized as NSF's
or OpenAI's. There are several distinct programs that may apply,
operating on different cadences. Try them in this order:

## Path 1 — Direct researcher outreach (highest signal, lowest friction)

**Send a personalized email** to Anthropic's safety research team. The
strongest path is via someone you know who is connected to Anthropic
(NIST AISI co-attendees, AAIF reviewers, formal-methods researchers
they've cited).

Subject:
> Pre-action authorization protocol with formal proofs — would your safety team review?

Body: paste sections 2 and 3 from `application.md` (the thesis + the
"why for Anthropic" section). Attach `application.md` as PDF.

Target inboxes (verify these are still active before sending):
- safety@anthropic.com — generic safety inbox; lower-priority but reads
- research@anthropic.com — research operations
- A specific researcher — better. Possible names: members of Anthropic's
  Alignment, Interpretability, or Frontier Red Team. Look at recent
  Anthropic papers in arXiv on agent safety, AI autonomy, or formal
  methods — the lead author is the right inbox.

## Path 2 — Anthropic Research API Access program

If/when Anthropic publicly opens applications for free or discounted
API access for safety researchers, apply there. Historically these
have been announced on https://www.anthropic.com/news as time-bound
calls. Watch that page weekly for ~30 days; the call cycles.

Application content: use sections 1, 4, 5, 6 from `application.md`.

## Path 3 — Frontier Model Forum (when this becomes a path)

Anthropic is a founding member. The Frontier Model Forum has historically
funded AI Safety Research grants ($10M+ pool). If/when applications
open, EP is a strong fit. Watch https://www.frontiermodelforum.org/ —
check monthly.

## What to do this week regardless

Send Path 1 (direct outreach) email. Even if no funded grant program is
currently active, getting EP onto the radar of Anthropic's safety team
unlocks every future program — and Anthropic researchers cite work they
know about.

## Pre-flight checks before sending

- [x] EP repo is public, README clearly states formal-verification claims
- [x] `@emilia-protocol/verify` shipped on npm (proves the protocol is
      *reified*, not just a paper)
- [ ] One named advisor with Anthropic-adjacent credibility (NIST,
      AAIF, formal-methods academic). 30-min ask in your network is
      worth 10x the response rate.
- [ ] PDF version of `application.md` ready for attachment
      (`pandoc application.md -o ep-anthropic-research.pdf`)
