# Schmidt Sciences — Science of Trustworthy AI — Application Package

**Prepared:** 2026-06-12
**Applicant entity:** EMILIA Protocol, Inc. — Delaware C-corporation (for-profit)
**Founder / would-be PI:** Iman Schrock (solo). ORCID 0009-0004-0290-5433
**Funded deliverable (intended):** the open, Apache-2.0 *research* layer of EMILIA Protocol — machine-checked formal models, an open verifiable-evidence benchmark, and the published authorization-receipt standard.

---

## ELIGIBILITY VERDICT — READ FIRST

**EMILIA Protocol, Inc. is NOT directly eligible for the Schmidt Sciences Science of Trustworthy AI program, for two independent reasons:**

1. **Wrong applicant type (structural).** The program is "open globally to individual researchers, research teams, research institutions, and multi-institution collaborations across universities, national laboratories, institutes, and nonprofit research organizations." A **for-profit company is not an eligible applicant type.** There is no stated subaward or direct-industry track. (Source: official RFP page + Schmidt Sciences trackers, cited below.)

2. **Wrong timing (the 2026 cycle is closed).** The 2026 Science of Trustworthy AI RFP closed on **May 17, 2026, 11:59 PM Anywhere on Earth.** The opportunity page now reads "This opportunity has expired." Today is June 12, 2026 — **there is no open Schmidt Sciences AI grant a non-academic could submit to right now.** No 2027 cycle has been published yet, but the program is described as a standing 2026 *research agenda*, which signals an intended recurring cadence worth watching.

**The adjacent Schmidt programs do not rescue eligibility either:**
- **AI2050 Fellows / Schmidt Science Fellows** are *academic postdoctoral fellowships* restricted to recent PhDs nominated by partner institutions — not open to a solo for-profit founder, and not a grant to a company.
- Schmidt Sciences' AI focus area funds research centers and academic PIs, not companies.

**Therefore this package is NOT a direct application.** It is, in order:
- (A) the honest verdict and funder facts (this section);
- (B) the **realistic alternative** — an **academic-partner proposal outline** EP can hand to an eligible PI, where EP contributes the open standard + formal models + benchmark as the technical substrate and the PI is the applicant of record; plus **who to approach**;
- (C) a short **cover note** to the program's general inbox to open the partnership conversation and confirm next-cycle timing.

The strongest near-term move is **(B) + (C)**: find an academic PI in formal methods / AI evaluation, position EP's open artifacts as the research infrastructure their proposal builds on, and let *them* submit when the next cycle opens. EP's separate, *directly* for-profit-eligible funding routes (Manifund, LTFF, Foresight) are tracked in `docs/grant-applications/ai-safety-philanthropy/` and remain the primary money path; Schmidt is a credibility-and-scale play pursued *through* an academic partner, not instead of those.

---

## FUNDER FACTS (researched June 2026)

| Field | Detail |
|---|---|
| Program | **Science of Trustworthy AI** (Schmidt Sciences — Eric & Wendy Schmidt) |
| 2026 RFP status | **CLOSED.** Deadline was **May 17, 2026** (AoE). Opportunity page now reads "expired." |
| Open as of June 2026? | **No.** No open AI grant a non-academic can submit to today. Next cycle unannounced; standing "research agenda" suggests recurrence. |
| Award size | **Tier 1:** up to **$1,000,000** (1–3 yr). **Tier 2:** **$1M–$5M+** (1–3 yr). |
| Indirect-cost cap | **≤10%** of direct costs (a hard Schmidt policy). |
| Eligibility | Universities, national laboratories, institutes, nonprofit research organizations; individual researchers and multi-institution collaborations. **For-profit companies: not an eligible applicant type.** Cross-border and multi-PI collaborations encouraged/preferred. |
| Application mechanism | Submission portal at `schmidtsciences.smapply.io` (program path `science_of_trustworthy_ai_rfp_2026`) — **now closed**. Research agenda + RFP linked from the Schmidt Sciences trustworthy-AI pages. |
| LOI / pre-proposal | None published for 2026 — full proposal was the submission. |
| Program contact | **trustworthyai@schmidtsciences.org** (general program inbox). |
| Research pillars (target these) | (1) **Characterizing and Forecasting Misalignment**; (2) **Generalizable Measurements and Interventions** (evaluation science, construct + predictive validity); (3) **Oversight Under Capability Gaps and Multi-Agent Risks**. |

**Honest fit assessment.** Schmidt's three pillars are framed around *misalignment, evaluation validity, and oversight of superhuman/multi-agent systems* — model-internals-leaning trust science. EP is **complementary but not centered there**: EP is not about what a model *wants*; it is about producing **portable, offline-verifiable evidence of which named human authorized an exact irreversible action**, and the **formal-methods science** (machine-checked safety properties of an authorization state machine) plus a **new open benchmark** for verifiable-evidence/escalation coverage. That maps most naturally onto **Pillar 2 (generalizable measurement: a shared yardstick the field lacks) and Pillar 3 (oversight and multi-agent accountability: who owns an action when agents interact)**. It is an *honest stretch into* the agenda, best carried by a formal-methods or evaluation PI who already sits inside it — which is exactly why the partner route, not a direct application, is the right framing.

---

## (B) ACADEMIC-PARTNER PROPOSAL OUTLINE

*Posture: the academic PI is the applicant of record (Tier 1, ≤$1M, 1–3 yr). EP / Iman Schrock is a **collaborator and technical-substrate provider** — the open standard, the verifiers, the formal models, and the benchmark are the research infrastructure the proposal extends. EP receives no Schmidt funds, or a minimal subaward at the PI institution's discretion, with all funded outputs Apache-2.0. This keeps the applicant eligible and the deliverables open.*

### Working title
*Formal Foundations and an Open Benchmark for Verifiable Human-Authorization Evidence in Multi-Agent AI Systems*

### Pillar alignment
- **Pillar 2 — Generalizable Measurements:** the headline deliverable is a public, versioned benchmark with construct validity for a property the field cannot currently measure — *escalation-policy completeness and boundedness*: does an oversight policy gate **every** irreversible action class without over-escalating into uselessness, and can an adversarial or prompt-injected agent game the escalation trigger?
- **Pillar 3 — Oversight & Multi-Agent Risks:** the science of **attributable oversight** — when interacting agents take irreversible actions, producing third-party-verifiable evidence of which named human authorized which action, and treating the *absence* of such evidence for a gated action as a forensic finding rather than ambiguity.

### Research aims (3, milestone-checkable, all outputs Apache-2.0)

**Aim 1 — Extend the machine-checked formal foundations of authorization evidence.**
Today EP ships **26 TLA+ safety properties and 22 Alloy assertions (15 core + 7 federation), 0 counterexamples, re-run in CI.** These cover the authorization state machine. The funded research **extends the formal coverage to the parts currently specified-but-not-proven** — WebAuthn challenge binding, the Approver Directory inclusion proofs, append-only log checkpoints, and the m-of-n approval flow — with every counterexample search published. This is the trustworthy-AI science: *proving*, not asserting, the safety properties of an oversight mechanism, and making the proofs reproducible by reviewers who do not trust the authors.

**Aim 2 — Build and release an open verifiable-evidence / escalation benchmark.**
A public corpus + runnable scorer measuring (a) *completeness*: every irreversible action class is gated by a human-authorization requirement; (b) *boundedness*: the policy does not over-escalate into operational uselessness; (c) *adversarial robustness*: a prompt-injected or misaligned agent cannot manufacture a valid authorization or evade the escalation trigger. This gives the field a shared, independently runnable yardstick for **oversight coverage** — directly serving Pillar 2's call for measurement with construct and predictive validity. Released Apache-2.0; any lab or vendor can score their own system.

**Aim 3 — Advance the open standard toward independent, multi-implementation verification.**
Carry the IETF Internet-Draft `draft-schrock-ep-authorization-receipts` (currently **-01**, including **PIP-007** — the agent's *signed escalation reason*, framed honestly as a claim by an identified-but-never-trusted initiator, **not** model introspection) toward the next revision and toward a non-author independent implementation. Multiple interoperable implementations is the IETF bar; an independent academic implementation is also the cleanest demonstration that the trust property does not depend on trusting the originating company.

### What EP contributes on day one (de-risks the proposal)
This is not a proposal to start. The substrate already ships and is independently checkable:
- The published standard (`draft-schrock-ep-authorization-receipts-01`, incl. PIP-007).
- npm `@emilia-protocol/verify` **1.4.0** (verify anywhere, zero-dependency) and `@emilia-protocol/issue` **0.2.0** (issue locally) — `npx @emilia-protocol/verify receipt.json` runs offline today.
- Verifiers in **JavaScript, Python, and Go** plus a conformance suite.
- **26 TLA+ properties + 22 Alloy assertions**, 0 counterexamples in CI; **85 red-team cases**.
- NIST AI RMF and EU AI Act mappings (`docs/compliance/`).
- Two essays grounding the thesis: *The Model Is the Crumple Zone* and *Why Authorization Is Not Proof*.

### What an authorization receipt proves — stated with discipline (the research is honest or it is nothing)
The receipt proves a precise, narrow thing: that **a named, enrolled human produced a user-verified, device-bound signature over the exact hash of one irreversible action, under a stated policy, before that action executed** — verifiable offline, by anyone, forever. **The receipt proves** that and only that. It does **not** prove the decision was wise, lawful, or uncoerced; it does not prove the rendering was faithful; it does not establish real-world identity beyond the key↔approver enrollment. (See `docs/RECEIPT-CLAIMS.md`.) A proposal that overclaims would fail peer review; EP's published discipline about non-claims is itself an asset to an academic co-applicant.

### Budget shape (PI-led, ≤10% indirect per Schmidt policy)
Tier 1, ≤$1M, 1–3 years, held at the PI's institution. Indicative split: graduate/postdoc researcher time on Aims 1–2; PI oversight; an optional minimal subaward to EP for standards/benchmark engineering with **all outputs Apache-2.0**; the remainder to formal-verification compute and an independent reviewer. (Schmidt also offers compute *in lieu of* cash — relevant for large counterexample searches.)

### Crumple-zone hook (one paragraph, for the PI's significance section)
When an AI agent takes an irreversible action a human should not have authorized, blame flows to the most legible party — usually the model or its provider — while the human who actually made the call disappears from the record. This is the *moral crumple zone* (Elish, 2019) inverted: the most nameable component is no longer the operator nearest the machine, it is the model. The fix is not better model introspection; it is **portable, verifiable evidence of who authorized what, produced before the action ran.** Building the *formal foundations* and the *measurement science* for that evidence — provably correct oversight mechanisms, and a benchmark that says whether an oversight policy actually covers what it claims — is squarely the science of trustworthy AI.

### WHO TO APPROACH (academic PIs / labs to carry this)
Target a PI whose existing agenda already sits inside Schmidt's pillars, so EP is a substrate they extend rather than a detour:
- **Formal-methods + security faculty** who work on protocol verification (TLA+/Alloy/Tamarin/ProVerif lineage) — the natural home for Aim 1. EP's models give them a live, real-world target system.
- **AI-evaluation / measurement labs** (groups publishing on eval validity, agent benchmarks, oversight) — the natural home for Aim 2's benchmark; aligns to Pillar 2 directly.
- **Multi-agent systems / AI-governance-technical groups** working on oversight and accountability — for Aim 3 and the significance framing.
- **Institutions already engaging Schmidt's trustworthy-AI RFP** (e.g., university research-development offices that publicized the 2026 RFP, such as University at Albany's OCFR) — their sponsored-programs offices know the mechanics and the cadence.
- Practical sourcing: query OpenReview / recent NeurIPS-SoLaR, IEEE S&P / USENIX Security, and CAV/POPL author lists for the intersection of *formal verification* and *AI agent oversight*; prioritize PIs with prior Schmidt or NSF Formal Methods funding.

---

## (C) COVER NOTE — to open the partnership conversation

*Send to **trustworthyai@schmidtsciences.org** (general program inbox), and in parallel to candidate academic PIs. Honest, short, no overclaim.*

> Subject: Open formal-methods + benchmark infrastructure for the Science of Trustworthy AI — partnership inquiry
>
> Hello,
>
> I lead EMILIA Protocol, an open (Apache-2.0) standard and reference implementation for **authorization receipts**: cryptographic, offline-verifiable proof that a named human approved an exact irreversible AI-agent action, under a stated policy, before it executed. The work is already public — an IETF Internet-Draft (`draft-schrock-ep-authorization-receipts-01`), verifiers in JavaScript, Python, and Go, and **26 machine-checked TLA+ properties plus 22 Alloy assertions at 0 counterexamples in CI**. Anyone can verify a receipt offline today: `npx @emilia-protocol/verify receipt.json`.
>
> I understand the Science of Trustworthy AI program funds academic and nonprofit research institutions, not for-profit companies, and that the 2026 cycle has closed. I am writing for two reasons. First, to ask whether a future cycle is planned and on what cadence. Second, to offer EP's open artifacts as **research infrastructure for an eligible academic PI**: the formal models are a live target for extending machine-checked safety proofs (WebAuthn challenge binding, m-of-n approval, log checkpoints), and we are building an **open benchmark for oversight-policy completeness and adversarial robustness** that maps onto your measurement and multi-agent-oversight pillars. EMILIA Protocol, Inc. is a for-profit Delaware C-corp; the deliverables I am describing are Apache-2.0 and useful to the field regardless of the company. We have no customers and are not asking Schmidt to fund the company — the right structure is a PI-led proposal that builds on the open standard, with us as a technical collaborator.
>
> If you can point me toward the next cycle's timing, or to faculty already working in this space who might co-develop a proposal, I would be grateful. The repository, the draft, and the essays (*The Model Is the Crumple Zone*; *Why Authorization Is Not Proof*) are all public.
>
> Thank you,
> Iman Schrock — Founder, EMILIA Protocol · ORCID 0009-0004-0290-5433

---

## SUBMISSION / NEXT ACTIONS

1. **Do not attempt a direct submission** — the 2026 portal is closed and a company is ineligible regardless.
2. **Send the cover note (C)** to `trustworthyai@schmidtsciences.org` to confirm next-cycle timing and open a partnership path.
3. **Identify 2–3 academic PIs** per the "who to approach" list; share the partner outline (B) and the public artifacts; aim for the PI to be applicant-of-record next cycle.
4. **Keep EP's primary money path on the for-profit-eligible routes** (`docs/grant-applications/ai-safety-philanthropy/` — Manifund, LTFF, Foresight). Schmidt is a credibility/scale play *through* a partner, not a substitute.
5. **Watch for the next RFP** on the Schmidt Sciences trustworthy-AI pages and via the program inbox.

---

## SOURCES

- 2026 Science of Trustworthy AI RFP (official, now expired): https://www.schmidtsciences.org/opportunity/2026-science-of-trustworthy-ai-rfp/
- Science of Trustworthy AI program + research agenda: https://www.schmidtsciences.org/trustworthy-ai/ · https://www.schmidtsciences.org/trustworthy-ai-research-agenda/
- AI focus area: https://www.schmidtsciences.org/focus-area-ai/
- University at Albany OCFR listing (academic-channel example): https://www.albany.edu/ocfr/news/2026-schmidt-sciences-science-trustworthy-ai
- AI2050 / Schmidt Science Fellows (academic-only fellowships): https://schmidtsciencefellows.org/selection/who-can-apply/
- Program inbox: trustworthyai@schmidtsciences.org
- EP artifacts cited: `standards/draft-schrock-ep-authorization-receipts-01.md`, `formal/PROOF_STATUS.md`, `docs/RECEIPT-CLAIMS.md`, `packages/verify/`, `packages/issue/`, `docs/compliance/`, `docs/essays/the-model-is-the-crumple-zone.md`, `docs/essays/why-authorization-is-not-proof.md`
