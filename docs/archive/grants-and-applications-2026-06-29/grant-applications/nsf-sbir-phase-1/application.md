# NSF SBIR Phase I — Project Pitch

**Topic:** AI — Artificial Intelligence / AI7 Technologies for Trustworthy AI
*(secondary fit: CA — Cybersecurity and Authentication / CA8 Personal Authentication, CA3 Data Privacy and Integrity)*
**Applicant:** Iman Schrock / EMILIA Protocol (US-owned small business)
**Solicitation:** NSF 26-510 (America's Seed Fund SBIR/STTR)
**Award sought:** up to $305,000 / 6–18 months (Phase I)
**Submission portal:** https://seedfund.nsf.gov/ (Project Pitch first)
**Format:** Project Pitch (plain text in NSF's web form)

> NSF SBIR Phase I is a two-step process: the **Project Pitch** is short
> and free; if NSF's program staff respond with an invitation, you write
> the full Phase I proposal for the actual award. This document is the
> Project Pitch. Each section corresponds to a required field in the NSF
> Project Pitch web form. NSF's mandate is to fund **revolutionary, not
> evolutionary** R&D — unproven, high-impact technical risk. This pitch is
> framed around the *unsolved research problems*, with the shipped protocol
> presented only as evidence the team can execute.
>
> Word limits: Technology Innovation 500, Technical Objectives 500,
> Market Opportunity 250, Company and Team 250.

---

## 1. Briefly Describe the Technology Innovation
*(NSF asks: up to 500 words. What is the innovation, where did it come from, and why is it revolutionary rather than evolutionary?)*

AI agents are starting to take irreversible real-world actions — redirecting
payments, changing vendor bank accounts, mutating infrastructure — and when
one goes wrong, there is no tamper-evident answer to a simple question: *under
whose authority, and under what policy, did this happen?* Logs are
operator-controlled and forgeable. There is no cross-operator way to prove,
after the fact, that an action was authorized by an accountable party.

EMILIA Protocol (EP) is an open standard and reference implementation for
**verifiable authorization receipts for AI-agent actions**. EP gates a
high-stakes action behind a cryptographic ceremony that binds, in one
offline-verifiable receipt: *who* initiated it (an authority chain), *under
what policy* (the exact policy version, hash-pinned), *for what* (the action's
canonical hash), *with what evidence* (verifiable claims and optional named
human signoff), and *at what time, with what one-time nonce*. The receipt
proves the binding. Anyone with the public key verifies it without trusting
the operator's servers — the way a signed certificate is checkable without
calling the issuer.

This is being standardized in the open. The Internet-Draft
**draft-schrock-ep-authorization-receipts-01** (posted June 2026) specifies
the wire format. The -01 revision adds **PIP-007 initiator escalation
attestation**: the receipt records *why* the agent escalated to a human
(`escalation_trigger`: irreversibility, magnitude, uncertainty, novelty,
authority gap, or a fired policy rule) — turning an agent's judgment to "stop
and ask a human" into evidence rather than a silent code path.

What is new is not any single primitive (Ed25519, Merkle anchoring, nonces are
all standard). It is the **canonical binding** of identity, authority, policy,
and action into one artifact whose safety holds under adversarial scheduling —
and the claim that this binding can be made *interoperable across mutually
distrusting operators*. EP is to AI-agent action authorization what TLS is to
the web: a common protocol that lets independent parties interoperate without
trusting each other.

Execution evidence that the base case is real and the team ships:
- **Published, zero-dependency packages:** `@emilia-protocol/verify` 1.4.0 and
  `@emilia-protocol/issue` 0.2.0 on npm — issue locally, verify anywhere.
- **Three independent verifiers** (JavaScript, Python, Go) plus a **public
  conformance suite**, so receipts are checkable across language ecosystems.
- **Formal verification in CI:** 26 TLA+ safety properties model-checked, 22
  Alloy assertions on the core relations, and 7 additional Alloy assertions on
  the federation model — 0 counterexamples.
- **85 cataloged red-team cases** against the ceremony.
- **NIST AI RMF and EU AI Act compliance mappings.**

The protocol specification and reference verifiers are open source. The
revolutionary bet — and the reason this needs *research*, not just engineering —
is that the hardest properties (when an agent *must* escalate; whether
federation is provably safe; whether evidence survives a 10-year crypto
migration) are still open. Those are Phase I.

## 2. Technical Objectives and Challenges
*(NSF asks: up to 500 words. What R&D will reduce technical risk, and why is it hard?)*

The single-operator base case is shipped and verified. The Phase I research
risk is in four open problems that the production system deliberately does
*not* yet solve. NSF funds exactly this kind of unproven risk.

**Objective 1 — Escalation-policy synthesis: *when must an agent escalate?***
PIP-007 records *that* an agent escalated and its stated reason. The unsolved
research question is the policy itself: given an action's irreversibility,
magnitude, novelty, and the authority gap, can we *synthesize and verify* a
decision boundary for when a human signoff is mandatory — one that is sound
(never auto-approves an irreversible high-magnitude action) without being so
conservative it escalates everything? The challenge is formalizing
"irreversibility" and "magnitude" as machine-checkable predicates over
heterogeneous action types, then proving the synthesized policy refuses the
adversary's edge cases. This is the core intellectual contribution.

**Objective 2 — Formal verification of multi-operator federation.**
EP today runs a live two-operator federation — but, stated honestly, both
operators are EMILIA-run, so it proves the *mechanism*, not *safety under a
malicious operator*. The 7 federation Alloy assertions are a start; they are
not a proof that a Byzantine operator cannot forge a receipt another operator's
verifier accepts, nor that trust-delegation cycles are impossible under bounded
depth. Phase I extends the TLA+ model to federation primitives (operator
registry, trust delegation, cross-receipt consumption) and proves
cross-operator unforgeability under an adversarial operator.

**Objective 3 — Post-quantum crypto-agility for long-lived evidence.**
A receipt may need to be verifiable in 2040. Ed25519 signatures will not
survive a cryptographically relevant quantum computer, yet the evidentiary
value of a receipt is precisely its *longevity*. The research challenge is a
crypto-agility scheme — likely hybrid classical+PQ signatures with a documented
migration path — that lets a verifier validate a decade-old receipt against the
algorithm in force when it was issued, without breaking canonical
determinism across the algorithm boundary.

**Objective 4 — Rendering faithfulness (I-D §11.3).**
A signature over an action *hash* is worthless if the human approver was shown a
misleading rendering of that action — a presentation attack that harvests a
genuine signature over a misunderstood action. Phase I researches
independently-authored, verifiable renderings and a way to bind the rendering a
human actually saw to the receipt, closing the gap between *what was signed* and
*what was understood*.

**Risk and feasibility.** The reference protocol is in production with real
handshake creation, signoff, consumption, and audit-event emission; 26 TLA+
properties and the conformance suite mitigate base-case risk. The honest,
*unsolved* parts above are the interesting ones, and they are why this is
research. No customers yet; pilots are in active outreach.

## 3. Market Opportunity
*(NSF asks: up to 250 words. Customer profile and the near-term pain point.)*

Near-term commercial focus: **county government payment-integrity**. When a
vendor's bank account is silently changed and a county wires a real payment to a
fraudster, there is currently no tamper-evident record tying the change to a
named, accountable human under a known policy. This vendor-bank-account-change
fraud is a concrete, recurring, budgeted pain for county finance, treasury, and
audit offices.

**EMILIA GovGuard** packages EP as a 60-day, observe-mode pilot ($25,000
fixed): it watches one workflow the county chooses — e.g., vendor
bank-account changes — and produces verifiable evidence of which actions
*would have* required a named signoff, with no payment credentials and no
integration to start. We have an active outreach motion to roughly 74 county
finance offices. To be clear: these are prospective pilots in outreach, not
signed customers.

The wedge generalizes. The same authorization-receipt layer serves AI-agent
platforms shipping agents that take real actions (whose enterprise buyers
demand action-binding controls) and financial-fraud defense at community banks.
The protocol and verifiers stay open source (Apache 2.0); revenue comes from
the managed issuance/audit service and domain-specific productized surfaces
(GovGuard), mirroring the PostgreSQL-vs-managed-cloud precedent rather than an
open-core bait-and-switch.

## 4. Company and Team
*(NSF asks: up to 250 words. Background and current status of the company and key team.)*

**EMILIA Protocol** is a US-owned small business (sole founder; entity
formation underway), with its place of business in the United States and all
R&D performed in the US. It meets SBIR eligibility: more than 50% owned by a
US citizen, fewer than 500 employees, organized for profit.

**Iman Schrock** — Principal Investigator and founder. Authored the full EP
stack: the IETF Internet-Draft (draft-schrock-ep-authorization-receipts-01),
the TLA+ formal specification (26 properties) and Alloy models (22 core + 7
federation assertions), the zero-dependency reference verifiers in JavaScript,
Python, and Go, the published npm packages, the public conformance suite, the
85-case red-team catalog, the NIST AI RMF / EU AI Act compliance mappings, and
the GovGuard pilot. Has written the founding essays establishing this
category at emiliaprotocol.ai/essays.

**Phase I personnel plan.** The PI leads the research. Planned contracts: an
independent cryptographic auditor (e.g., Cure53 or equivalent) to review the
post-quantum crypto-agility design, and a part-time formal-methods collaborator
for the federation TLA+ extension. All work performed in the United States by
US persons.

**PI-employment note (important):** NSF requires the PI's *primary* employment
(at least 51%) to be with the small business **at the time of award**, not at
pitch time. The founder currently holds outside employment; the plan is to meet
the 51%-employed requirement upon award. This is the one eligibility item the
founder must resolve before accepting an award — see submission.md.

---

## Submission notes (delete before pasting into NSF form)

- The NSF Project Pitch web form has a separate field per section above. Paste
  each section into its corresponding field; headings here are for clarity only.
- Word limits per NSF: Technology Innovation 500, Technical Objectives 500,
  Market Opportunity 250, Company and Team 250. Current text is within budget.
- **Topic choice:** Submit under **AI / AI7 Technologies for Trustworthy AI**
  as primary (the innovation is verifiable authorization for *AI-agent
  actions* — a trustworthy-AI accountability mechanism). CA (Cybersecurity and
  Authentication) — specifically CA8 Personal Authentication, CA3 Data Privacy
  and Integrity, CA2 Cryptography — is a defensible secondary home. Confirm with
  a program officer before submitting; the right topic saves a round trip.
- After submission, NSF program staff respond by email with either an
  invitation to submit a full Phase I proposal or feedback/decline. An
  invitation is valid for the next two full-proposal deadlines.
- Honesty guardrails kept throughout: no customers (pilots in outreach only);
  "irreversible," not "consequential"; "the receipt proves," never "EMILIA
  proves"; the two-operator federation is disclosed as both-EMILIA-operated.
