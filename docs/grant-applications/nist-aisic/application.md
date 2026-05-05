# NIST AI Safety Institute Consortium (AISIC) — Membership Application

**Program**: AISIC (US AI Safety Institute Consortium)
**URL**: https://www.nist.gov/artificial-intelligence/nist-ai-consortium
**Cost**: Free; requires CRADA (Cooperative Research and Development
Agreement) signature
**Reward**: Non-monetary — credibility, working-group access, direct
visibility into NIST's AI risk-management standards work, citation surface
**Process**: Email aiconsortium@nist.gov with letter of interest →
CRADA negotiation → onboarding to working groups
**Format**: Letter of interest, this document.

---

## 1. Cover paragraph

EMILIA Protocol (EP) — an open-standard, formally-verified pre-action
authorization protocol for AI agent systems — requests membership in
the AI Safety Institute Consortium and contributes infrastructure to
the working groups focused on agent governance, model risk management,
and verifiable trust.

## 2. Mission alignment with AISIC

NIST AISIC is chartered to develop the science, practice, and policies
of AI safety in measurable ways. EP contributes specifically to:

- **AI RMF measurement**: EP's compliance mapping spans 38 NIST AI RMF
  subcategories across all four functions (GOVERN, MAP, MEASURE, MANAGE).
  Each subcategory has a concrete protocol primitive (e.g. action-bound
  authorization implements MAP 1.6 "AI risks and benefits are
  characterized" with cryptographic specificity).
- **Authentication and auditability**: EP's trust-receipt mechanism
  produces tamper-evident, third-party-verifiable evidence of every
  consequential agent action — directly addressing GOVERN 6.1
  "Mechanisms are in place to inventory AI systems."
- **Federation and operator interoperability**: EP is designed for
  multi-operator deployments where independent operators cross-verify
  receipts via shared cryptographic proofs, mirroring the structure
  NIST is exploring for federated AI governance.

## 3. Concrete contributions EP can make

| AISIC working group / topic | EP contribution |
|---|---|
| AI RMF Profiles | EP-RMF-Mapping draft document (`docs/compliance/NIST-AI-RMF-MAPPING.md`) usable as a starting point for an Agentic-Systems profile. |
| Model evaluation & red-teaming | 85 cataloged adversarial test cases (`docs/conformance/RED_TEAM_CASES.md`) covering authorization-bypass classes (replay, policy-mutation, signoff-spoofing, delegation-cycle). |
| Pre-deployment testing methodologies | Working open-source verification library (`@emilia-protocol/verify`) demonstrating reproducible action-binding verification. |
| Agentic systems risk management | Reference protocol with 26 TLA+ theorems verified, available as a citation surface for "what verified action-binding looks like." |
| Federated trust / cross-operator verification | Federation specification (`docs/FEDERATION-SPEC.md`) and reference-implementation work in progress. |

## 4. Capacity to participate

EP's protocol author and PI is committed to:

- 8 hours / month direct WG participation across 1–2 working groups
- Open-source contribution of any artifacts produced for AISIC
  (Apache 2.0 — irrevocable)
- Publication of AISIC-relevant findings under NIST's preferred
  attribution conventions
- Hosting one (1) annual review of the formal verification status
  with any AISIC member that requests it

## 5. Eligibility and CRADA readiness

- US-based small business (single-founder, Delaware C-corp formation
  in progress)
- All work performed by US persons
- IP posture: Apache 2.0; no IP encumbrance that would conflict with
  CRADA standard terms
- Available to sign CRADA upon NIST's invitation

## 6. Public artifacts referenced

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- Formal proofs: `formal/PROOF_STATUS.md`
- AI RMF mapping: `docs/compliance/NIST-AI-RMF-MAPPING.md`
- EU AI Act mapping: `docs/compliance/EU-AI-ACT-MAPPING.md`
- Red-team catalog: `docs/conformance/RED_TEAM_CASES.md`
- Audit methodology: `docs/security/AUDIT_METHODOLOGY.md`

## 7. Contact

Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai
github.com/emiliaprotocol
