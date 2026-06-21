# SFF Speculation Grant — How to Submit

**Program:** Survival and Flourishing Fund (SFF) — **Speculation Grants** (the rolling, low-friction entry point).
**Where:** https://survivalandflourishing.fund/ → **Speculation Grants** → application form.
**Why this route first:** Speculation Grants are the rolling on-ramp and the **prerequisite to be guaranteed eligible** for the larger SFF **S-Process** round. Applying here both funds near-term work and secures eligibility for the big round.
**Timing:** Rolling — applications are reviewed by SFF speculation grantors on an ongoing basis, not against a single annual deadline. No fixed window to wait for.
**Eligibility:** Incorporated for-profit or nonprofit organizations, globally. EMILIA Protocol, Inc. (Delaware C-corp) qualifies; state the for-profit status plainly.
**Contact:** via the SFF site (the Speculation Grants page lists the current contact / questions channel). Use team@emiliaprotocol.ai as the applicant address.

## What to attach / link

SFF speculation grantors reward concrete, verifiable work. Provide, as links:

- **The open-source repository** (Apache-2.0) — the source of every claim.
- **The live demo** — https://www.emiliaprotocol.ai (`/quorum` product page + working multi-party demo).
- **The conformance suite** — `conformance/` and `node conformance/run.mjs`; call out the **9 EP-QUORUM-v1 vectors agreeing across JS / Python / Go** (`conformance/vectors/quorum.v1.json`).
- **The multi-device E2E** — `e2e/multi-party-quorum.spec.js` (passing).
- **The formal models** — `formal/PROOF_STATUS.md` (26 TLA+ theorems, 0 counterexamples) plus the Alloy models.
- **The IETF drafts** — `draft-schrock-ep-authorization-receipts-01` (and the enforcement-point / Eye profiles in `standards/`).

## Field mapping (paste plan)

The form is short. Map `application.md`:

| SFF field | Paste from `application.md` |
|---|---|
| Project / org name | EMILIA Protocol, Inc. — human-in-the-loop control for autonomous AI agents |
| What is the project? | "The risk this addresses" + "Why the two-person rule matters for safety" |
| Why is it important (for the long-term future)? | The risk framing + "Why this is a control mechanism, not a research agenda" |
| Use of funds | "What the Speculation Grant funds" (the two deliverables); request **$10k–$50k** |
| Track record | "Track record and transparency" |
| Honesty / limitations (if asked) | "What this is honest about" (do/don't-prevent + enforcement classes) |
| Links | the attach/link list above |

## Notes
- **Lead with the safety framing**, not the commercial one: a fail-closed, cryptographic gate so a misaligned / compromised / prompt-injected agent cannot *unilaterally* execute an irreversible high-stakes action, and the two-person rule means one compromised approver is insufficient.
- **Be explicit about the boundary** (collusion / coercion not prevented, only made attributable; enforcement classes). SFF reviewers value calibration; the honesty *is* the credibility.
- **State intent to apply to the next full S-Process round** so the eligibility on-ramp is on record.
- **Do not re-pitch** venues already submitted (Manifund, LTFF done; OpenAI Cybersecurity, Anthropic Research, NSF SBIR, NIST AISIC drafted). SFF is independent; no conflict.
- Log status in `docs/grant-applications/README.md` after submitting.
