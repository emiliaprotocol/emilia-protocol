<!-- SPDX-License-Identifier: Apache-2.0 -->
# The Reliance Play — turning a GovGuard pilot into rungs 3 & 4

**Purpose.** Produce the one milestone that uncaps fundability: **an auditor (or
oversight body) relies on an EP receipt as evidence.** A June-2026 investor review
scored EP *Fundability today 5.5/10 → 8.5/10 after first design partner / auditor
reliance event.* The gap is not technology — it's proof someone besides the founder
relies on it. **This is the #1 GTM objective; it outranks further protocol work.**

It maps directly onto the seed deck's reliance ladder:
- **Rung 3 — Design partner:** an org runs gated high-risk actions and emits EP
  receipts on the verifiers. *Achieved the moment a pilot goes live in observe mode.*
- **Rung 4 — Auditor reliance:** an auditor actually **uses** a receipt as evidence
  in a real control test. *The venture-grade milestone.* One pilot, structured right,
  produces both.

## What counts as the reliance event (capture ONE, in writing, attributable)
- An internal or external **auditor cites/uses an EP receipt** in a real control test
  or workpaper.
- A government **oversight body** (state auditor, IG, legislative committee) accepts an
  EP receipt as verifiable evidence of human authorization.
- A **compliance review** (healthcare, financial) accepts EP evidence.

**The artifact to capture:** a single attributable sentence, approved for external use —
e.g. *"[Office] verified an EMILIA receipt offline as part of [evaluation/audit]."* —
plus (ideally) the workpaper/control-test reference. That sentence goes on deck slides 4
& 5 (flip "→ 2026" to "✓") and into the next investor update. Do **not** claim it before
it exists.

## Vehicle: the existing 60-day observe-mode pilot, made reliance-first
Base offer: [`GOVGUARD-PILOT-OFFER.md`](./GOVGUARD-PILOT-OFFER.md) /
[`COUNTY-FINANCE-OBSERVE-PILOT.md`](./COUNTY-FINANCE-OBSERVE-PILOT.md). One change: the
success criterion becomes **"an auditor relied on a receipt,"** not "auditors received a
packet." Structure:

1. **Scope one high-risk workflow** — vendor bank-account changes ≥ $X, or benefit
   routing. Narrow is good.
2. **Observe mode, read-only feed — zero enforcement risk.** This is the objection-killer
   that gets a fast yes: GovGuard never blocks anything in the pilot.
3. **Emit an EP receipt** for each flagged action.
4. **The reliance step (the whole point):** mid-pilot, sit with the org's internal auditor
   (or their external auditor) and walk them through **verifying a real flagged action's
   receipt offline** — `npx @emilia-protocol/crash-test verify <receipt>` — then have them
   note it in a control test / workpaper.
5. **Deliverable:** the auditor's sign-off citing the receipt + the approved reliance
   sentence.

**Why observe-mode + auditor-first wins:** no enforcement risk → fast approval; and the
auditor is the *only* person who can produce the milestone that actually moves valuation.
The IT buyer alone gets you rung 3; the **auditor walkthrough** gets you rung 4.

## Targets — warm threads first (the auditor/oversight function, not just IT)
- **California Dept. of Technology** — already in the GenAI vendor-evaluation; ask for a
  scoped observe pilot on one workflow, with their evaluators as the "auditor."
- **CA Assembly committee (Josh Tosney)** — July reconnect; legislative interest can open a
  county/state finance pilot.
- **County finance / audit offices** — the vendor-bank-account-change fraud vector; the
  internal auditor is the buyer who grants reliance.
- **In-Q-Tel / DataTribe** gov-adjacent customers; **healthcare-AI vendor** whose compliance
  review accepts EP evidence (the clinical double-check).

**Rule:** target the person who can *grant* the reliance event — the auditor / oversight
function — not only the IT or security buyer.

## Sequencing & propagation
- Prioritize this above more drafts/verifiers/theorems. One reliance event ≈ +3 points of
  fundability and re-anchors the raise.
- When it lands: (a) flip the deck's validation + ladder slides to ✓; (b) send a one-line
  investor update to everyone in [[project_emilia_investors]] (Paladin, Forgepoint, Boldstart,
  Squadra, Scout, Lytical); (c) record it in memory.

Related: [[project_emilia_investors]] · [[project_emilia_gtm]].
