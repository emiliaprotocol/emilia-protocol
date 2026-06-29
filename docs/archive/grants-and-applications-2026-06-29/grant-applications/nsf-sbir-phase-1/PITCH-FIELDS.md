# NSF SBIR Phase I — Project Pitch (as submitted)

**Status:** Project Pitch submitted/ready 2026-06-13 via seedfund.nsf.gov (NSF 26-510).
**Topic:** AI7 — Technologies for Trustworthy AI (CA — Cybersecurity & Authentication as secondary).
**Award if invited + funded:** up to $305,000 over 6–18 months.
**Pitch response time:** ~1–2 months. Full proposal only if invited; target the **Nov 4, 2026** deadline.

The pitch is free and requires NO registrations. The full proposal (if invited) requires
SAM.gov + Research.gov + SBIR Company Registry — start SAM now (up to 3 weeks; UEI backlog).

---

## Eligibility self-assessment (all Yes)
1. Technological innovation / durable advantage — Yes (authorization receipts: a new primitive; no incumbent produces portable, offline-verifiable proof).
2. Risky, unproven R&D — Yes (escalation-decision verification, open federation, post-quantum agility are genuinely unsolved).
3. Significant national/economic importance — Yes (agent accountability, payment-fraud, government integrity; EU AI Act / NIST AI RMF).
4. Hard to replicate / sustainable advantage — Yes (formal proofs + IETF standards position + conformance).
5. Commercial potential — Yes (government program-integrity, financial institutions, enterprise agent platforms).
6. Qualified, dedicated team — Yes.
7. Engaged project lead (PI key role) — Yes (founder/PI).

---

## Field 1 — The Technology Innovation (2,528 / 3,500 chars)
EMILIA Protocol's innovation is a new security primitive: an authorization receipt — cryptographic, offline-verifiable proof that a named human approved an exact, irreversible AI-agent action, under a stated policy, before it executed. Unlike OAuth or API keys (which prove a caller holds a scope, not that it authorized this action), decision engines like AuthZEN/OPA (which answer "may this happen" at decision time but emit no portable artifact), or SIEM logs (operator-controlled records produced after the fact), a receipt is verifiable by any third party with open-source code and a public key — independent of the operator's runtime, logs, or survival.

The receipt format is built and formally modeled. The high-risk R&D Phase I must reduce to practice lies in three unproven areas where even an expert team can fail:

(1) Verified escalation-decision logic. The hardest open question in agent autonomy is WHEN an agent must stop and obtain human authorization. Today this is hand-written policy. The research is to make the escalation decision itself formally analyzable: synthesize and verify escalation policies that are provably complete (no irreversible action executes ungated) AND bounded (they do not over-escalate into uselessness), and that resist an adversarial or prompt-injected agent gaming the trigger. Proving completeness against an adaptive adversary is unsolved.

(2) Formally-verified open federation. A receipt is only as trustworthy as the network of verifiers that can check it without a trusted center. Proving safety — no forged cross-operator acceptance; sound revocation and key-rotation propagation — across many INDEPENDENTLY operated verifiers under Byzantine conditions is unproven at scale (today: two operators, 7 machine-checked federation assertions).

(3) Post-quantum crypto-agility for long-lived evidence. Receipts must verify decades later; classical signatures will not survive that horizon. Migrating signature suites without breaking existing offline verifiers, and re-anchoring historical logs, is an open formal-methods and cryptography problem.

Why adopted, why durable: the work is standards-track (IETF Internet-Draft, at -01) and open (Apache-2.0), with independent verifiers in three languages and machine-checked safety (26 TLA+ properties, 22 Alloy assertions, 0 counterexamples). The advantage is not a feature; it is a verifiable evidence layer no incumbent produces, hardened by formal proof — hard to replicate and positioned to become the interoperable standard.

---

## Field 2 — The Technical Objectives and Challenges (2,398 / 3,500 chars)
Phase I will prove the three high-risk innovations are reducible to practice, each with a measurable success criterion and a managed challenge.

Objective 1 — Verified escalation-decision logic. Task: formalize escalation invariants (every irreversible action class is gated; gating is minimal) in TLA+/Alloy, synthesize escalation policies that satisfy them, and red-team them against frontier agent models attempting to evade the trigger via prompt injection. Challenge: completeness against an adaptive adversary trades off against over-escalation. Management: treat it as a measured optimization — success = zero ungated irreversible actions across the adversarial corpus AND false-escalation below a target rate; release the corpus as an open benchmark so the claim is independently checkable.

Objective 2 — Formally-verified open federation. Task: extend the federation model from two operators to N, add a Byzantine-operator adversary, and prove no forged cross-operator acceptance plus sound revocation and key-rotation propagation; encode the proofs as an executable conformance suite. Challenge: independence — both current operators are EMILIA-run. Management: the concrete milestone is standing up an external, non-EMILIA operator that passes conformance, converting a modeled property into a demonstrated one.

Objective 3 — Post-quantum crypto-agility. Task: define a versioned, dual-suite receipt (classical + ML-DSA), prove existing offline verifiers accept it unmodified, and demonstrate re-anchoring of historical checkpoints under a PQ log key. Challenge: migration without a flag day or breaking deployed verifiers. Management: the wire format already carries a version tag; Phase I proves a backward-compatible rollout end-to-end.

Cross-cutting challenge — rendering faithfulness: cryptography proves a key signed a hash, not that the human saw the true action. Management (bounded, honest): structured action rendering plus a signed display attestation narrows the gap; we state precisely what remains out of scope rather than overclaim.

De-risking assets in hand: a published IETF draft, three independent verifiers, a conformance suite, 26 TLA+ and 22 Alloy machine-checked properties re-run in CI, and an 85-case red-team suite — evidence the team can execute formal-methods-grade R&D, so Phase I risk is concentrated in the open problems above, not in basic capability.

---

## Field 3 — The Market Opportunity (1,317 / 1,750 chars)
Customers and beneficiaries. The first wedge is government program integrity: county and state finance and audit offices that must prove a named human approved disbursements and vendor bank-account changes — a 60-day observe-mode pilot (GovGuard) is in active outreach. Adjacent near-term markets: financial institutions facing payment and vendor-change fraud, and enterprises deploying AI agents that hold credentials to move money or data. Each shares one need: portable, after-the-fact proof of who authorized an action — evidence that survives vendor turnover, acquisition, or SaaS sunset, a procurement value an operator-controlled log cannot offer.

Competitive landscape. Identity and decision systems (OAuth, AuthZEN, OPA, Cerbos) answer "may this happen" at decision time but produce no portable proof; SIEM/audit logs are operator-controlled and after-the-fact; approval-workflow tools capture the click, not a verifiable artifact. Converging standards efforts (PSEA, DRP, CHEQ) validate the category; EMILIA is co-shaping the shared verifier core at the IETF and is the only entry pairing offline, multi-language verification with machine-checked formal proofs. That combination — open standard, formal assurance, first-mover standards position — is why it can compete and become the interoperable default.

---

## Field 4 — The Company and Team (1,299 / 1,750 chars)
EMILIA Protocol, Inc. is led by founder and principal investigator Iman Schrock, who authored the entire stack now in evidence: the IETF Internet-Draft (draft-schrock-ep-authorization-receipts, -01), the TLA+ and Alloy formal models (26 + 22 machine-checked properties), an 85-case red-team suite, offline verifiers in JavaScript, Python, and Go, and the published npm toolkit (@emilia-protocol/verify, @emilia-protocol/issue). Iman holds a key technical role in the company and leads the Phase I R&D. Background spans trust systems, cryptographic protocols, and regulated-industry software.

Gaps and plan. The team is currently solo — the honest gap for the formal-methods-heavy objectives. Phase I funds a part-time collaborator with formal-verification and applied-cryptography depth to co-execute the escalation-synthesis and federation proofs and to respond to an independent cryptographic audit. External technical scrutiny is being built through active engagement with the NIST AI Consortium and the IETF secdispatch co-authors (PSEA, DRP) — review capacity without headcount. Commercial motivation is concrete: converting the GovGuard observe-mode pilot in outreach into a first paid deployment is the near-term objective, with the open standard and conformance program as the durable moat.

---

## If invited: full-proposal prep checklist
- [ ] SAM.gov registration — financial-assistance authority only (START NOW; up to 3 weeks)
- [ ] Research.gov company registration (after SAM; ~48h)
- [ ] SBIR Company Registry → Business Concern Control ID (SBC ID)
- [ ] PI primary-employment plan: ≥51% employed by the company AT AWARD (not at submission)
- [ ] Commercialization Plan (the section reviewers weight most): strongest evidence = 1+ named county pilot LOI — convert a GovGuard outreach reply before the full proposal
- [ ] Review NSF's Generative AI (GAI) memo for any disclosure expectation
- [ ] Three review criteria the full proposal must hit: Intellectual Merit (the formal-methods R&D), Broader Impacts (open standard, public benefit, gov integrity), Commercial Impact (the pilot → paid path)
