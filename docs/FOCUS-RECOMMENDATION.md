# EP Single-Vertical Focus Recommendation

**Status:** v1 (Apr 2026).
**Audience:** Founders, maintainers, investors.
**Assertion:** EP is currently positioning itself across four markets (government fraud, financial infrastructure, enterprise privileged actions, AI/agent governance). This is three too many for the next 12 months. This document argues for a single pick and explains the logic.

---

## 1. The premise

A pre-PMF protocol company chasing four markets will lose to a pre-PMF protocol company chasing one. This is not a unique insight; it is the modal failure pattern at seed-to-Series A. Four markets splits engineering attention, confuses buyers, muddies the narrative, and — most damagingly — means no single reference account grows big enough fast enough to produce the precedent flywheel EP actually needs.

The counter-argument — "but trust-before-action applies to all four" — is correct in the abstract and wrong in practice. The abstraction does apply to all four. The GTM motion, evidence demands, sales cycles, legal framework, integration partners, and buyer persona are radically different. Trying to sell "the same protocol" to a federal agency, a bank, an enterprise IT org, and an AI platform means doing four different sales jobs with one pipeline. The math doesn't work.

Pick one. Win one. Expand from a position of strength.

---

## 2. Candidate evaluation

Criteria for the pick:
- **Time-to-first-pilot**: shorter is better.
- **Reference value**: how much does a public success here unlock downstream?
- **Evidence fit**: does EP's current evidence (100/100 audit, formal proofs, red-team history) map to what this buyer wants?
- **Wedge durability**: does winning here produce structural lock-in (see `ECONOMIC-MOAT.md`)?
- **Competitive density**: who else is already selling here, and how well?

Rough scoring (1-5, higher better):

| Vertical | Time-to-pilot | Reference value | Evidence fit | Wedge | Competition | **Total** |
|---|---|---|---|---|---|---|
| Government fraud / payment integrity | 2 | **5** | **5** | **5** | 4 | **21** |
| Financial institutions (treasury, BEC) | 3 | 4 | 4 | 4 | 3 | **18** |
| Enterprise privileged actions | 4 | 3 | 3 | 3 | 2 | **15** |
| AI / agent execution governance | **5** | 3 | 2 | 3 | 2 | **15** |

- **Government fraud**: slow procurement (scored 2 on time-to-pilot) but extreme reference value if won (a Treasury or Medicare Integrity Program logo alone justifies the round), excellent evidence fit (100/100 audit + TLA+ proofs + Apache 2.0 exactly maps to federal procurement requirements), strong wedge (NIST standards track + federal cross-certifications = durable moat). Highest total even with slow cycles.
- **Financial institutions**: reasonable on every axis but does not uniquely stand out. The buyer wants evidence we can partially provide but also wants integration depth we currently lack (core banking system plugins, SWIFT integration, etc.). Likely second priority.
- **Enterprise privileged actions**: mid on every axis. The commercial market exists (HashiCorp Boundary, CyberArk, Delinea) and is well-served. EP has no structural advantage here until Accountable Signoff becomes a checkbox requirement (not yet).
- **AI / agent governance**: fastest to pilot (every AI platform is scoped to ship "agent safety" features), but the evidence the buyer wants is not the evidence we have. They want runtime efficiency benchmarks, MCP-server performance, low-latency decisioning. Our evidence is correctness-heavy, which is valuable but not what they shop for in 2026. Revisit in 12-18 months when the buying pattern matures.

---

## 3. Recommendation: Government fraud / payment integrity as the single focus for the next 12 months

This is not a close call.

- **Largest reference value.** One public federal agency pilot is worth ten enterprise pilots in narrative terms.
- **Best evidence fit.** The buyer explicitly demands things we've already built: formal proofs, open source, NIST-alignable, auditable. Most other verticals want things we can't show yet (customer logos, hard ROI studies, tight vendor integrations).
- **Durable wedge.** A federal certification line item for "EP-conformant" — even a mid-level one — compounds for years. Every downstream buyer that needs to sell to federal gets steered toward EP.
- **We already have the right positioning materials.** `docs/GOVERNMENT-PILOT-PROPOSAL.md`, `docs/briefs/GOVERNMENT_PILOT_BRIEF.md`, `docs/NIST-ENGAGEMENT-PLAN.md`. The investment in this vertical is already sunk cost.
- **Realistic about the cycles.** Federal procurement is 12-18 months at best. Accept that. Build the pipeline wide enough that three or four parallel conversations are running; one will land.

---

## 4. What to explicitly de-scope for 12 months

De-scoping is the hard part. "Keep doing all four, just focus more on gov" is not a strategy; it is a hedged bet that loses to any bet.

### 4.1. Financial institutions
- Maintain `docs/FINANCIAL-INSTITUTIONS-PILOT-PROPOSAL.md`. Respond to inbound. Do NOT build FI-specific integration work. Do NOT pitch FI roadshows.
- If an FI wants to pilot, they get the same reference implementation as the government pilot. No custom work.
- Revisit in month 12 when government pilot progress either validates or invalidates the thesis.

### 4.2. Enterprise privileged actions
- Pause new outreach. Maintain content (the existing proposals and briefs). Make no new commitments.
- Accept inbound only if the buyer is willing to pilot on the existing reference implementation. No enterprise SaaS features, no admin consoles, no RBAC UIs beyond what exists.

### 4.3. AI / Agent governance
- The MCP positioning stays — it helps the narrative. But do not build agent-specific features (runtime policy engine, agent-tier SLAs, etc.).
- If the market matures in 12 months such that AI platforms start buying, we re-enter with a product-market fit advantage. If it doesn't mature, we didn't waste engineering.

### 4.4. Explicit cuts
- No new vertical-specific proposals between now and month 12.
- No new integrations that don't serve the government pilot.
- The commercial team (if any) is 100% focused on one vertical.
- Engineering has one customer persona. Everything else is noise.

---

## 5. Concrete 12-month milestones

### Months 1-3: pipeline breadth
- 15 federal + state-level conversations active.
- 3 pilot scope documents in review with specific buyers.
- At least one in-person meeting with Treasury Fiscal Service, CMS Medicaid Integrity, or a state-level PIB.
- Deliverables: tight pilot scope doc, security questionnaire responses ready, FedRAMP-path analysis.

### Months 4-6: pilot landing
- 1 signed pilot. Even a no-contract LOI pilot counts if the scope is serious.
- Begin the FedRAMP or equivalent authorization path that the buyer's team signals is their blocker.
- Publish the first case study (anonymized if needed).

### Months 7-9: pilot operation
- Run the pilot with real data.
- Measure: signoff completion rates, policy false-positive rates, incident response time improvements, audit time savings.
- These are the numbers that populate every subsequent pitch.

### Months 10-12: expansion
- Pilot → production case study.
- Second federal conversation becomes the second pilot.
- NIST working group submission (if not already in progress) uses the pilot evidence as support.

End of year: one public federal deployment, one production case study, a concrete evidence pipeline for Series A. That is plausibly enough to defend a $40-75M Series A against a hyperscaler-eats-us thesis, because the precedent moat and the specific customer reference don't come in a tin for a fork to copy.

Compare to: four vertical pipelines running simultaneously, no single logo to point to, and a "broad applicability" narrative that reads as "we haven't focused yet."

---

## 6. What could break this recommendation

Things that would legitimately cause a rethink:

- **A sudden, large FI relationship.** If a top-five bank says "we want to be your first production deployment and we'll sign in 90 days," take it and re-focus. Bird in hand.
- **Hyperscaler announces a competing product.** If AWS announces AWS-Trust in month 3, the pace of the government pilot needs to accelerate, and the foundation + conformance body work (per `ECONOMIC-MOAT.md`) becomes urgent rather than important.
- **A legal precedent in a disputed signoff.** Either direction — a favorable precedent accelerates everything; an unfavorable one requires a pause and rethink of the evidentiary claims.
- **NIST or another standards body moves faster than expected.** If a working group invites a reference contribution in month 4, that becomes the top priority regardless of vertical.

Outside these scenarios: stay focused. Discipline is a feature.

---

## 7. Restate to be unambiguous

- **One vertical for the next 12 months: government fraud / payment integrity.**
- **Primary buyers: US Treasury Fiscal Service, CMS Medicaid Integrity Program, state-level Program Integrity Bureaus.**
- **Secondary buyers** (accept inbound, don't pursue): FI treasury teams.
- **Defer entirely**: enterprise privileged actions, AI/agent governance product work.
- **End-of-year proof**: one live federal pilot, one public case study, one NIST working group engagement.

If anything in the roadmap is not on that list, delete it or defer it.
