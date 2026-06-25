# AFWERX SBIR Phase I — Open Topic Proposal Scaffold
### EMILIA Protocol: Verifiable Human Oversight of Autonomous AI Actions

**Status:** scaffold (fill `[CONFIRM]` / `[FILL]` before submission)
**Vehicle:** AFWERX SBIR open topic (propose-your-own-solution to a capability gap). Watch
DSIP (defensesbirsttr.mil) for the monthly BAA; also fits named topics — Trusted AI &
Autonomy, Runtime-Assured Autonomy, CHORD (Collaborative Human-Autonomy).
**Technical volume:** `EMILIA-human-in-the-loop-paper.pdf` is the technical core — attach/adapt.

> **#1 SUCCESS FACTOR (read first):** AFWERX open-topic awards hinge on a **DoD end-user /
> customer who wants it** (a Customer Memorandum / letter of support from a relevant program
> office). The tech is strong; the missing piece is a named DoD stakeholder. **Securing one
> is the critical pre-submission to-do** — seeds: the DIU Spectrum Strike entry, the
> Department of War "human-in-the-loop" paper submission, CDAO Responsible AI. [FILL: customer]

---

## 1. Identification & Significance of the Problem (the capability gap)
DoD Directive 3000.09 requires "appropriate levels of human judgment over the use of force,"
plus auditable, traceable, governable AI. The Jan-2026 AI Strategy for the Department of War
sets pace-setting autonomy projects (swarms, AI battle management) — accelerating autonomous
action while **human oversight remains unverifiable**. Today the record that a named human
authorized an autonomous action is an operator-controlled log: forgeable, backfillable,
un-auditable by an IG, coalition partner, or court without trusting the party under review.
**The capability gap: provable, tamper-evident, offline-verifiable human authorization for
autonomous and agentic actions in contested environments.**

## 2. Phase I Technical Objectives (feasibility)
1. Adapt the EMILIA authorization-receipt primitive to a DoD autonomy oversight use-case
   ([FILL: the customer's mission scenario] — e.g., HOTL weapons-release envelope, ISR
   tasking, or autonomous-platform command authorization).
2. Build a reference integration: receipts issued at the authorization boundary; fail-closed
   enforcement ("no verified human authorization → no effect").
3. Demonstrate offline / air-gap verification in a disconnected, contested-network setting.
4. Map the receipt fields to 3000.09 oversight requirements + produce the IG-grade audit
   artifact; validate against NIST AI RMF.
5. Multi-party (two-person rule / launch authority) via EP-QUORUM; bounded, revocable
   envelopes (human-on-the-loop).

## 3. Phase I Work Plan (~6 months)
- M1–2: requirements w/ the DoD end-user; threat model; scenario definition.
- M2–4: reference integration + air-gap verifier build; conformance vectors for the scenario.
- M4–5: contested-environment demonstration; 3000.09 / NIST crosswalk; red-team pass.
- M5–6: feasibility report + Phase II transition plan + customer demonstration.

## 4. Innovation & Related Work
EMILIA is the only effort that binds a **named, accountable human** to **one exact action**,
**offline-verifiable** without trusting the issuer, **fail-closed**, as an **open standard**.
Adjacent layers (agent identity/WIMSE, delegation/DRP, transparency logs/SCITT) are
complementary — EMILIA is the human-authorization apex that composes above them. (See the EP
IETF survey + architecture; this is the "who else is interested / how is it different"
answer.) Not blockchain (tamper-evident transparency log, not on-chain).

## 5. Commercialization & Dual-Use
- **Defense:** the verifiable human-control evidence layer for 3000.09 / RAI compliance —
  sold to programs/primes as the managed issuer + audit/evidence layer (open core free; the
  operated trust root is the business).
- **Civilian (dual-use, real traction):** U.S. state AI oversight (**Utah OAIP invited
  EMILIA into its third-party auditor solution-provider call**, 2026), finance, healthcare,
  critical infrastructure. EU AI Act Art. 14 is a parallel civilian forcing function.
- Model: standard given away (ubiquity + no lock-in); revenue = hosted issuer / approver
  directory / transparency log / compliance evidence pipeline. [FILL: Phase II $ + projections]

## 6. Key Personnel
- **Iman Schrock — Founder/PI.** [CONFIRM PI ≥51% employed by EMILIA Protocol, Inc. AT AWARD.]
  Track record: authored the EP IETF Internet-Drafts; formally-verified core; cross-language
  conformance. [FILL: technical co-PI / advisor if adding — strengthens the eng story.]

## 7. Past Performance & Proof
Open standard (Apache-2.0); IETF Internet-Drafts (authorization receipts, quorum); formally
verified (26 TLA+ theorems, 35 Alloy facts, 0 errors); 85 red-team cases; 3 independent
cross-language verifiers (JS/Python/Go) agreeing across the conformance suite; first external
adoption (COSA, IETF agent2agent WG); Utah OAIP engagement. [FILL: DoD customer letter.]

## 8. Submission checklist
- [ ] **DoD end-user / Customer Memorandum** secured ← the gate. [FILL]
- [ ] Watch DSIP for the open-topic BAA window (monthly); note topic # / dates. [FILL]
- [ ] SAM.gov registration current (CAGE cleared ✓); SBIR Company Registry / SBC ID. [FILL]
- [ ] PI employment ≥51% by EP at award. [CONFIRM]
- [ ] Technical volume = EMILIA-human-in-the-loop-paper.pdf (adapt to the scenario).
- [ ] Cost volume (Phase I ceiling per the BAA). [FILL]
- [ ] Dual-use commercialization narrative (Utah OAIP + civilian wedge).
