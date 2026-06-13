# Agency SBIR — DHS S&T and NIST (FY2026)

Two federal SBIR programs, researched together because both are a clean fit for
EMILIA Protocol and both are between solicitations as of June 2026. This file
holds, for each: current open/next status, the program-specific Phase I framing,
a paste-ready pitch, and submission instructions / what to watch.

> **Not a duplicate of NSF.** A separate NSF SBIR Project Pitch was already
> prepared under **AI7 — Technologies for Trustworthy AI** (see
> `../nsf-sbir-phase-1/`). This package is **DHS S&T SBIR** and **NIST SBIR**
> only. The NIST *SBIR* program here is distinct from the **NIST AI Consortium**
> letter of interest (see `../nist-aisic/`) — SBIR is a contract/award for R&D;
> the Consortium is a CRADA membership. Keep them separate in correspondence.

> **Verified June 12, 2026** against the official program pages and SBIR
> deadline trackers. Both FY2026 solicitations were disrupted by the SBIR/STTR
> authorization lapse that was resolved by **reauthorization on April 13, 2026**
> (program extended through Sept 30, 2031). As a result, neither DHS nor NIST
> had a live FY2026 SBIR solicitation open on the verification date. See the
> per-program status blocks below for the watch plan.

---

## Status summary (read this first)

| Program | Solicitation | Status (Jun 2026) | Phase I award | Topic fit | Fit (1–5) |
|---|---|---|---|---|---|
| **DHS S&T SBIR** | FY2026 (next; FY25 was 25.1) | **Not open — next window est. May–Jul 2026** | ~$150K / 6 mo (up to ~$200K some cycles) | Identity/data-integrity, critical-infrastructure, AI assurance | **4** |
| **NIST SBIR** | FY2026 NOFO (not yet released) | **Not open — page being updated post-reauthorization** | ~$100K (historically; reauth may raise caps) | Trustworthy-AI measurement / cryptographic assurance | **4** |

**Honest read on fit.** Both are a 4, not a 5, for the same reason: until the
FY2026 topics are published, the exact topic match is unconfirmed. DHS has a
strong *precedent* topic (FY25 **DHS251-004**, digital-trust / injection-attack
integrity for video identity verification) and standing mission areas
(critical-infrastructure resilience, identity/access) that EP maps onto cleanly.
NIST's program explicitly centers **AI measurement and trustworthy-AI standards**
— EP's native language — but NIST SBIR historically funds R&D against NIST's own
measurement-science mission, so the pitch must be framed as *measurement
infrastructure*, not a product. Re-score to 5 once a named matching topic appears.

---

# PROGRAM 1 — DHS S&T SBIR

## Status & key facts (DHS)

- **Program owner:** DHS Science & Technology Directorate (S&T). One major
  solicitation per year, ~15–30 topics, each authored by a DHS program manager
  against a specific capability gap.
- **FY2026 status:** **No open solicitation as of June 12, 2026.** The FY25
  solicitation (**25.1**) opened Jan 6, 2025 and closed Jan 21, 2025. The normal
  cadence is a pre-solicitation (historically Nov–Dec), a short open window, and
  a compressed ~30-day proposal period. The FY2026 cycle slipped due to the
  authorization lapse; trackers estimate the next DHS SBIR window in the
  **late-spring/early-summer 2026** range (May–Jul). **Watch for it.**
- **Phase I award:** firm-fixed-price contract, **~$150,000 over ~6 months**
  (some sources cite up to ~$200K; DHS S&T historically ~$150K). Phase II scales
  to roughly **$750K–$1.1M over ~24 months**.
- **Submission:** DHS S&T SBIR portal (`sbir2.st.dhs.gov`); solicitation posted
  on SAM.gov. There is a **pre-release contact window** (~2 weeks) where you may
  email the topic author with questions *before* the topic locks for proposals —
  use it.
- **Closest precedent topic (FY25 25.1):** **DHS251-004 — Securing Video
  Communications to Prevent Digital Injection Attacks** (establish and maintain
  *digital trust* in captured video for immigration virtual interviews). This is
  an identity-integrity / accountable-capture problem adjacent to EP's evidence
  layer. Standing DHS mission areas of interest: **Critical Infrastructure and
  Resilience**, **Identity & Access Management / zero-trust**, **AI for threat
  detection**.

## DHS angle (critical-infrastructure / identity / accountability)

DHS does not buy "trustworthy AI" in the abstract — it buys **accountability for
automated decisions inside critical-infrastructure and identity workflows**. The
EP framing for DHS:

> When an automated or AI-driven process takes an irreversible action against a
> critical-infrastructure or identity system — reconfiguring an OT control,
> approving an identity-proofing decision, changing an access grant — DHS and its
> components have no tamper-evident, operator-independent answer to *under whose
> authority, and under what policy, did this happen?* Logs are operator-controlled
> and forgeable. EP produces a cryptographic **authorization receipt** that binds
> who authorized the action, the exact hash-pinned policy, the action's canonical
> hash, the evidence (including optional named-human signoff), and a one-time
> nonce — verifiable offline by any party with the public key, including an
> inspector general or a downstream component that does not trust the issuer.

## DHS — paste-ready Phase I pitch (~250-word abstract + framing)

*(DHS Phase I proposals are short and topic-specific. Lead with the abstract
below; bind it to the exact FY26 topic number once published. Until then this is
the reusable core.)*

> **EMILIA Protocol: Offline-Verifiable Authorization Receipts for Automated
> Actions in Critical-Infrastructure and Identity Systems**
>
> Automated and AI-driven systems increasingly take irreversible actions inside
> homeland-security workflows — identity-proofing approvals, access-grant
> changes, operational-technology reconfigurations. When one is later disputed,
> there is no tamper-evident, operator-independent proof of who authorized it,
> under what policy, before it executed. Audit logs are controlled by the same
> operator whose action is in question, and they do not survive cross-component
> or cross-vendor handoff.
>
> EMILIA Protocol (EP) is an open (Apache-2.0) standard and reference
> implementation for **authorization receipts**: a single cryptographic artifact
> that binds, in one offline-verifiable record, *who* initiated an action (an
> authority chain), *under what policy* (the exact policy version, hash-pinned),
> *for what* (the action's canonical hash), *with what evidence* (verifiable
> claims and optional named-human signoff), and *at what time, with what one-time
> nonce*. The receipt proves the binding; any party with the public key verifies
> it without trusting the issuing operator — including an inspector general, a
> downstream component, or an air-gapped reviewer.
>
> EP is published as IETF Internet-Draft `draft-schrock-ep-authorization-receipts`,
> with zero-dependency verifiers in JavaScript, Python, and Go, a public
> conformance suite, and an air-gap installer for classified/disconnected
> deployment. Phase I delivers a DHS-scoped reference integration and an
> independently re-runnable verification harness proving cross-component receipt
> unforgeability under an adversarial operator.

**Phase I technical objectives (DHS).**
1. **DHS-scoped reference integration** of the receipt ceremony against one
   component-chosen workflow (e.g., an identity-proofing or access-change
   decision), in *observe mode* — produce receipts, change nothing.
2. **Air-gapped / disconnected verification** — demonstrate that a receipt issued
   inside a sensitive enclave verifies offline against the included verifier, no
   call-home (`deploy/airgap/`).
3. **Cross-component unforgeability** — extend the formal model to the
   multi-operator (cross-component/cross-vendor) case and show a Byzantine
   operator cannot forge a receipt another component's verifier accepts.
4. **NIST AI RMF alignment** — deliver the receipt-to-RMF evidence mapping
   (GOVERN/MAP/MEASURE/MANAGE) so the artifact plugs into existing federal AI
   risk documentation.

---

# PROGRAM 2 — NIST SBIR

## Status & key facts (NIST)

- **Program owner:** NIST Technology Partnerships Office (TPO).
  `nist.gov/tpo/small-business-innovation-research-program-sbir`.
- **FY2026 status:** **No open NOFO as of June 12, 2026.** The NIST SBIR page
  explicitly states it "is currently being updated to reflect the changes and
  improvements to the NIST SBIR Program resulting from the reauthorization"
  (program reauthorized **April 13, 2026**, extended through Sept 30, 2031), and
  directs applicants to "check back … for updates on when the next SBIR NOFO will
  be released." New solicitations post on `nist.gov/oam/funding-opportunities`
  and `grants.gov`; topics typically publish months before the deadline.
- **Phase I award:** historically **~$100,000** (NIST has run a lower Phase I
  cap than DOD/NSF; the 2026 reauthorization may raise caps — confirm against the
  released NOFO). Mechanism is a **grant/NOFO on grants.gov**, not a contract
  portal — different from DHS.
- **AI relevance:** NIST's FY2026 priorities direct substantial funding to **AI
  research and measurement science** (model evaluation, red-teaming,
  trustworthy-AI benchmarks). EP's category — verifiable evidence for AI-agent
  actions — is squarely a measurement primitive.
- **Distinct from the NIST AI Consortium.** The Consortium (CAISI, CRADA-based,
  `aiconsortium@nist.gov`) is handled in `../nist-aisic/`. SBIR is a separate
  funded R&D award. Do not conflate the two in any single email.

## NIST angle (AI measurement / trustworthy-AI assurance + RMF mapping)

NIST funds **measurement science**. The EP framing for NIST:

> Trustworthy-AI frameworks (the NIST AI RMF) tell organizations *to* establish
> accountability and human oversight for AI actions, but provide no **portable,
> verifiable unit of measurement** for whether a given irreversible AI-agent
> action actually was authorized by a named principal under a known policy. EP
> supplies exactly that unit: an authorization receipt an evaluator hands to a
> verifier to get back a yes/no, independent of the system that issued it. EP
> already maps this evidence onto the AI RMF across all four functions
> (`docs/compliance/NIST-AI-RMF-MAPPING.md`). Phase I researches the open
> measurement questions: how to formalize "irreversibility" and "magnitude" as
> machine-checkable predicates, and how to make the receipt's evidentiary value
> survive a multi-decade cryptographic migration.

## NIST — paste-ready Phase I pitch (~250-word abstract + framing)

> **EMILIA Protocol: A Measurement Primitive for Authorized AI-Agent Actions**
>
> The NIST AI Risk Management Framework asks organizations to govern, map,
> measure, and manage AI risk — including accountability and human oversight for
> consequential AI actions. What the framework lacks is a **portable, verifiable
> unit of measurement**: a way to take one irreversible AI-agent action and prove,
> independent of the system that performed it, that a named principal authorized
> it under a known, unaltered policy before it executed.
>
> EMILIA Protocol (EP) is an open (Apache-2.0) standard and reference
> implementation for **authorization receipts** — a single cryptographic artifact
> binding *who* authorized an action, *under what policy* (hash-pinned), *for what*
> (the action's canonical hash), *with what evidence* (verifiable claims and
> optional named-human signoff), at what time, with what one-time nonce. The
> receipt proves the binding and verifies offline against an open-source verifier;
> no trust in the issuer is required. EP publishes IETF Internet-Draft
> `draft-schrock-ep-authorization-receipts`, zero-dependency verifiers in three
> languages, a conformance suite, and an explicit NIST AI RMF mapping across all
> four functions.
>
> Phase I targets the open *measurement-science* questions: (1) formalizing
> "irreversibility" and "magnitude" as machine-checkable predicates over
> heterogeneous action types, so the decision to require human signoff is itself
> measurable and auditable; and (2) crypto-agility for long-lived evidence, so a
> receipt remains independently verifiable across a multi-decade signature-algorithm
> migration. Deliverables: a reference measurement profile mapping receipts to AI
> RMF subcategories, and a re-runnable conformance harness any evaluator can use to
> confirm a receipt without trusting the issuer.

**Phase I technical objectives (NIST).**
1. **Receipt-to-RMF measurement profile** — turn `NIST-AI-RMF-MAPPING.md` into a
   formal evaluation profile: which receipt fields evidence which subcategory, and
   the pass/fail predicate for each.
2. **Machine-checkable escalation predicates** — formalize irreversibility and
   magnitude so "a human must sign off here" is a measured, reproducible decision.
3. **Crypto-agility for long-lived evidence** — hybrid classical+PQ signatures with
   a documented migration path that preserves canonical determinism across the
   algorithm boundary.
4. **Independent conformance harness** — a published suite any third party (or
   NIST) re-runs to confirm a receipt's claims, extending the existing conformance
   suite and three-language verifiers.

---

## Shared evidence base (both programs)

Public, in-repo, citable in either proposal:

- **IETF Internet-Draft** `draft-schrock-ep-authorization-receipts` (-01),
  incl. **PIP-007** initiator-escalation attestation —
  `standards/draft-schrock-ep-authorization-receipts-01.md`.
- **Published packages:** `@emilia-protocol/verify` 1.4.0 and
  `@emilia-protocol/issue` 0.2.0 on npm (zero runtime dependencies) —
  `packages/verify/`, `packages/issue/`.
- **Three independent verifiers** (JavaScript, Python, Go) + a public
  **conformance suite** — `conformance/`, `CONFORMANCE.md`.
- **Formal verification in CI:** **26 TLA+ safety properties** model-checked
  (TLC 2.19; 413,137 states; 0 errors; T1–T26) and **22 Alloy assertions** with
  **0 counterexamples** (15 on the core model `formal/ep_relations.als`, 7 on the
  federation model `formal/ep_federation.als`) — `formal/PROOF_STATUS.md`.
- **85 cataloged red-team cases** — `docs/conformance/RED_TEAM_CASES.md`.
- **Compliance mappings:** NIST AI RMF (`docs/compliance/NIST-AI-RMF-MAPPING.md`)
  and EU AI Act (`docs/compliance/EU-AI-ACT-MAPPING.md`).
- **Air-gap installer** for disconnected/classified deployment — `deploy/airgap/`.

## Applicant / eligibility (both programs)

- **EMILIA Protocol Inc** — a for-profit US small business; sole founder
  (Iman Schrock); place of business in the US; all R&D performed in the US by
  US persons. Meets SBIR baseline: >50% US-citizen owned, <500 employees,
  organized for profit.
- **PI:** Iman Schrock (ORCID 0009-0004-0290-5433), author of the full EP stack.
- **Registrations needed before either award (start now, ~1–2+ weeks each):**
  **SAM.gov** (UEI / entity registration), **SBA Company Registry**, and an
  **SBIR.gov account**; for NIST add a **grants.gov** registrant role; for DHS
  add a **`sbir2.st.dhs.gov` portal** account. SAM.gov is the long pole.
- **No customers.** GovGuard and the financial-institutions package are pilot
  *offers* in active outreach, not signed engagements.

## Honesty guardrails (kept throughout — verified by `check-language-governance.js`)

- "Irreversible," not "consequential" (except where quoting the NIST RMF's own
  wording).
- "The receipt proves," never "EMILIA proves" / no `EmiliaClient`.
- 26 TLA+ properties; **22 Alloy assertions** (15 core + 7 federation), 0
  counterexamples — not inflated.
- No customers — pilots are offers in outreach only.
- No EIN / entity-formation specifics asserted beyond "for-profit US small
  business."
- The live two-operator federation is disclosed as both-EMILIA-operated; Phase I
  is what makes cross-operator/cross-component safety a *proven* claim.
