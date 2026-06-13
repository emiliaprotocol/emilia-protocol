# Submission Checklist — DIU Project Spectrum Strike (Pitch Round)

**Vehicle:** DIU Commercial Solutions Opening / Prize Challenge — Project Spectrum Strike.
**Pitch due:** 2026-06-15. **Rounds:** Pitch → MVP (2026-07-10) → Live demo (2026-08-25).
**Applicant:** EMILIA Protocol, Inc. (Delaware C-corp) · Iman Schrock, Founder/PI · team@emiliaprotocol.ai.

> ⚠️ **RE-CONFIRM ON THE LIVE PORTAL BEFORE SUBMITTING.** Every requirement, date, file-format
> rule, and round detail below was captured from the solicitation as recorded in
> `../application.md` (§1, §4a) at an earlier date. DIU CSOs and prize challenges change
> wording, deadlines, and submission mechanics. **Open the live solicitation first**, re-read
> the actual ask, and reconcile any difference before you upload anything. If the live wording
> differs from the requirement→primitive map in `PITCH-DECK.md` slide 5, fix the deck to match
> the live wording — do not submit the captured wording on faith.

---

## 0. The honest framing to lead with (read this first)

- EP is the **authorization & audit module**, not the spectrum-parsing/triage engine. Bid it as:
  1. a **teaming / subcontract** "governance & audit module" under a spectrum-AI **prime**, or
  2. a **standalone audit-module** evaluation if a prime isn't reachable in time.
- EMILIA Protocol, Inc. is **pre-revenue, no customers** (pilots offered, none signed), **solo**
  founder. Do not imply a team, a deployment, or a customer anywhere in the submission.
- **Realistic note:** a solo founder pitching a DIU CSO with two days' notice, for a challenge
  whose core ask is a spectrum-AI engine EP does not build, is a **stretch**. The highest-value
  move is almost certainly a **teaming overture to a spectrum-AI prime** that is already bidding
  the triage engine — EP slots in as the governance/audit module they will need to satisfy the
  human-on-the-loop and auditable-governance requirements. See §5.

---

## 1. Where to submit (portal path)

1. Go to the DIU open-solicitations portal: **diu.mil/work-with-us/open-solicitations**.
2. Find **Project Spectrum Strike** in the active list. (If it has closed or moved, stop — see
   the re-confirm warning above; do not submit to a stale link.)
3. Open the solicitation detail page and read the **current** submission instructions: format
   (slide PDF vs. portal form), page/slide limit, file-size cap, and any required fields.
4. Follow the portal's own submission flow. DIU prize challenges sometimes route through a
   challenge platform rather than a direct upload — use whatever the live page specifies.

---

## 2. What the pitch round expects

- A short **pitch deck** (the solicitation as captured calls for **≤10 slides**) — provided here
  as `deck.html` (open in a browser → **Print → Save as PDF**) with copy mirrored in
  `PITCH-DECK.md`.
- A clear **requirement→primitive map**: each Spectrum Strike ask → the exact EP primitive that
  satisfies it. This is `PITCH-DECK.md` slide 5 and the corresponding `deck.html` section.
- The **dual-use abstract**, trimmed to the pitch's word limit — source is `../application.md`
  §2 (250-word paste-ready). Trim to whatever the portal allows.
- A **demonstrable capability**: the 60-second offline issue→mutate→fail demo (`DEMO-SCRIPT.md`).
  Even at the pitch stage, "you can run this yourself in one minute" is the differentiator.
- The **formal-assurance numbers** (26 TLA+ / 413,137 states / 22 Alloy / 85 red-team / IETF I-D
  -01 / 3-language verifiers) — `PITCH-DECK.md` slide 7.

---

## 3. Rounds / timeline

| Round | Date | What's expected |
|---|---|---|
| Pitch | **2026-06-15** | ≤10-slide deck + requirement→primitive map + demo capability |
| MVP | 2026-07-10 | EP wired to a reference triage agent via MCP; receipts for simulated high-risk releases; offline audit bundle |
| Live demo | 2026-08-25 | End-to-end: agent escalates → named human signs off → receipts verify offline → a mutated release fails |

Spectrum Strike being **multi-round** is a tailwind: a strong pitch buys time, and the MVP/demo
rounds are where EP's installable, offline-verifiable nature shows best. **Re-confirm all three
dates on the portal** — they were captured earlier.

---

## 4. Registration prerequisites

- **DIU CSOs / prize challenges are lighter than SBIR.** For the **pitch** round, EP does **not**
  need SAM.gov registration or a UEI, and no SBIR Company Registry / DSIP account. (This is part of
  why DIU is the better immediate shot than SBIR for EP right now.)
- **If it advances toward an award/agreement,** SAM.gov registration (and a UEI) **will** be
  required, as for any federal award. Start SAM.gov registration **in parallel** if the pitch
  advances — it can take time, so don't wait for the award notice.
- Have ready (no sensitive credentials in the submission itself):
  - Legal entity name: **EMILIA Protocol, Inc.** (Delaware C-corp).
  - Founder/PI: **Iman Schrock**, ORCID 0009-0004-0290-5433.
  - Public contact: **team@emiliaprotocol.ai**.
  - Repo / standard: **github.com/emiliaprotocol/emilia-protocol**; IETF I-D
    `draft-schrock-ep-authorization-receipts` (-01) on datatracker.
- **Do NOT include** an EIN, banking/payment details, or any secret in the pitch package. None of
  it is needed at the pitch stage.

---

## 5. The teaming play (recommended)

Because EP is the governance/audit module and **not** the spectrum engine, the strongest outcome
is to **team under a spectrum-AI prime**:

- **Who to approach:** any vendor or team already bidding the Spectrum Strike triage engine, or an
  established spectrum-coordination / EW / RF-autonomy contractor. They must satisfy DIU's
  human-on-the-loop and **auditable-governance-as-policy-changes** requirements — EP is the
  shortest path to both.
- **The one-line offer:** "Your triage agent calls EP's MCP server before any irreversible
  release; EP returns a named-human authorization receipt that verifies offline. You get the
  human-on-the-loop control and the 0%-false-negative audit trail as a drop-in module."
- **What EP needs from the prime:** (1) the agent's escalation hook (call EP before an irreversible
  release), (2) the policy definitions to hash-pin, (3) named-approver enrollment.
- **If no prime is reachable by 2026-06-15:** submit EP as a **standalone governance/audit module**
  pitch and use the pitch itself as the teaming overture — DIU may broker the introduction to a
  prime that needs exactly this layer.

---

## 6. Pre-submission gate (do every item)

- [ ] **Re-open the live DIU solicitation** and reconcile every requirement, date, and format rule
      against this package. Fix the deck where the live wording differs.
- [ ] Convert `deck.html` to PDF (browser → Print → Save as PDF) and confirm it is ≤10 slides and
      within any page/size cap.
- [ ] Trim the `../application.md` §2 abstract to the portal's word limit.
- [ ] Confirm the deck states the honest scope (EP = audit/authorization layer, not the triage
      engine) and the teaming posture — slide 9.
- [ ] Confirm **no customers / no team / no deployment** is implied anywhere.
- [ ] Confirm **no EIN, no payment credentials, no secrets** appear in any file.
- [ ] Dry-run the 60-second demo end to end (`DEMO-SCRIPT.md`) on the machine you'll present from,
      offline.
- [ ] If teaming: send the prime overture (§5) **before** the deadline, not after.
- [ ] Both repo governance gates pass on these files:
      `node scripts/check-language-governance.js` and `node scripts/check-docs-secrets.js`.

---

*Sources: `../application.md` §1/§4a (captured DIU solicitation language), §2 (dual-use abstract);
DIU open-solicitations portal (diu.mil/work-with-us/open-solicitations). Re-confirm every number
on the official portal before submitting.*
