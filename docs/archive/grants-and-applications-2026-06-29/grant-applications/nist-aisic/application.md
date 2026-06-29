# NIST AI Consortium — Letter of Interest

<!--
========================= VERIFIED JUNE 2026 =========================
STATUS CHANGE since this file was first drafted (May 5, 2026):

The "AI Safety Institute Consortium (AISIC)" was renamed the
"NIST Artificial Intelligence Consortium" (a.k.a. "NIST AI Consortium").
The parent institute (formerly the US AI Safety Institute) is now the
Center for AI Standards and Innovation (CAISI), under the Department of
Commerce. The CONSORTIUM was NOT killed — it was re-scoped and REOPENED
for new members.

Key facts verified June 11–12, 2026:
- New Federal Register notice published May 29, 2026 (doc 2026-10779)
  reopening membership and expanding scope to "science-based and
  empirically backed guidelines and standards for AI measurement."
- First selection period begins June 2026; letters accepted on an
  ONGOING basis with review periods "likely occurring biannually."
  Selection is first-come, first-served on complete letters.
- Contact / submission email is UNCHANGED: aiconsortium@nist.gov
  (webform, email, or hardcopy to NIST, 100 Bureau Drive, Mail Stop
  8900, Gaithersburg, MD 20899).
- A CRADA is STILL the join mechanism: selected participants enter a
  consortium Cooperative Research and Development Agreement with NIST.
- Letters MUST NOT include proprietary information and must state:
  (1) the role(s) the organization will play, (2) the specific
  expertise it brings, (3) the products/services/data/technical
  capabilities it will use, plus org address and point of contact.
- 280+ member organizations currently.
- Six task groups (membership lands you here, not "working groups"):
  AI TEVV (Testing, Evaluation, Verification & Validation) Zero Draft;
  Annotation for AI Risks & Validity; AI Evaluation and Measurement
  Methods; BENGAL (Bias Effects & Notable Generative AI Limitations);
  AI Documentation Cards; Chemical and Biological Security.

Sources:
- https://www.nist.gov/news-events/news/2026/05/nist-expands-ai-consortiums-scope-calls-new-members
- https://www.federalregister.gov/documents/2026/05/29/2026-10779/nist-artificial-intelligence-consortium
- https://www.nist.gov/artificial-intelligence/nist-ai-consortium/submit-letter-interest-join-nist-ai-consortium
- https://www.nist.gov/artificial-intelligence/nist-ai-consortium
- https://fedscoop.com/nist-ai-consortium-reemerges-new-name-scope-members/

WHAT CHANGED IN THIS FILE vs the May 5 draft:
- Title/program renamed AISIC -> NIST AI Consortium; parent is CAISI.
- "Working groups" reframed as the six published TASK GROUPS; best fit
  is now AI TEVV + AI Evaluation and Measurement Methods + AI
  Documentation Cards (not "Agentic Systems," which is no longer a
  named group).
- LOI body rewritten to the three required content elements above.
- Asset figures refreshed to the verified June 2026 state and corrected
  to what is actually machine-checked in the repo (see note in §3).
- Honesty pass: "irreversible" not "consequential"; the receipt proves,
  never "EP proves"; no customer claimed (GovGuard is an OFFER).
======================================================================
-->

**Program:** NIST Artificial Intelligence Consortium (formerly the AI
Safety Institute Consortium / AISIC), housed under the Center for AI
Standards and Innovation (CAISI), U.S. Department of Commerce.
**Submission:** Letter of interest by webform or email to
`aiconsortium@nist.gov`. Reopened for new members May 29, 2026 (Fed.
Reg. 2026-10779); accepted on an ongoing basis, first-come first-served
on complete letters, with review periods roughly biannual.
**Cost:** Free; selected participants enter a consortium Cooperative
Research and Development Agreement (CRADA) with NIST.
**Format:** One-page letter of interest (this document). No proprietary
information.

---

## Letter of interest

To the NIST AI Consortium team,

EMILIA Protocol (EP) requests to join the NIST AI Consortium. EP is an
open, formally specified protocol that produces a portable, signed
**authorization receipt**: a tamper-evident record of who approved an
irreversible AI-agent action, under which policy, before it executed.
The receipt is the artifact — it verifies anywhere, with open-source
code, independent of the system that issued it.

**The role we will play.** The Consortium's purpose is science-based,
empirically backed standards for AI *measurement*. EP brings one
concrete, open, verifiable unit of measurement the framework currently
lacks: a receipt that an evaluator can hand to a verifier and get back
a yes/no on whether a named principal authorized a specific irreversible
action under a hash-locked policy. We map this evidence onto the NIST AI
RMF across all four functions — GOVERN, MAP, MEASURE, MANAGE — in
`docs/compliance/NIST-AI-RMF-MAPPING.md`, and we offer it as input to
the AI TEVV, AI Evaluation and Measurement Methods, and AI Documentation
Cards task groups.

**The specific expertise we bring.** EP is built standards-first and
proof-first:

- **An IETF Internet-Draft** at revision **-01**
  (`draft-schrock-ep-authorization-receipts-01`), defining the receipt
  schema, verification rules, and the PIP-007 initiator-escalation
  attestation. Open and citable.
- **Machine-checked safety.** 26 TLA+ safety properties verified by TLC
  2.19 (413,137 states, 0 errors); 22 Alloy assertions verified with 0
  counterexamples — 15 on the core relational model (`ep_relations.als`)
  and 7 on the cross-operator federation model (`ep_federation.als`).
  All run in CI. Status and scope: `formal/PROOF_STATUS.md`.
- **Reproducible verification.** Published npm packages
  `@emilia-protocol/verify` 1.4.0 and `@emilia-protocol/issue` 0.2.0 —
  "issue locally, verify anywhere," zero runtime dependencies — plus
  verifiers in three languages and a conformance suite, so a third party
  can confirm a receipt without trusting us.
- **Framework mappings.** NIST AI RMF (above) and EU AI Act
  (`docs/compliance/EU-AI-ACT-MAPPING.md`), and a county
  payment-integrity pilot package (GovGuard) that exercises the receipt
  in a real audit workflow.

**The technical capabilities we will use in Consortium activities.**
The IETF draft as a citation surface; the formal models and CI as
evidence of measurement rigor; the open-source verifiers and conformance
suite as a reference any member or NIST can run; the RMF mapping as a
starting point for an evaluation/documentation profile; and the GovGuard
pilot package as a worked, sector-specific example. All EP artifacts are
Apache-2.0. We do not propose to replace identity or authorization
standards — EP adds a verifiable evidence layer on top of them.

We are a U.S.-based small entity, all work performed by U.S. persons,
with no IP encumbrance that would conflict with standard CRADA terms,
and are ready to sign a CRADA on NIST's invitation.

**Organization and point of contact:**
EMILIA Protocol — Iman Schrock, Founder
`team@emiliaprotocol.ai` · github.com/emiliaprotocol/emilia-protocol ·
essays: https://www.emiliaprotocol.ai/essays

---

## Public artifacts referenced

- IETF I-D: `standards/draft-schrock-ep-authorization-receipts-01.md`
- Formal proof status: `formal/PROOF_STATUS.md`
- NIST AI RMF mapping: `docs/compliance/NIST-AI-RMF-MAPPING.md`
- EU AI Act mapping: `docs/compliance/EU-AI-ACT-MAPPING.md`
- Verifier package: `packages/verify` (`@emilia-protocol/verify` 1.4.0)
- Local issuer: `packages/issue` (`@emilia-protocol/issue` 0.2.0)
- County pilot package: `docs/pilots/GOVGUARD-PILOT-OFFER.md`
- Essays: https://www.emiliaprotocol.ai/essays
