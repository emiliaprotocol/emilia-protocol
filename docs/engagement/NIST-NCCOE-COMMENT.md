<!-- SPDX-License-Identifier: Apache-2.0 -->
# NIST NCCoE comment — Software & AI Agent Identity and Authorization

**Target:** NCCoE concept paper *"Accelerating the Adoption of Software and Artificial
Intelligence Agent Identity and Authorization"* (posted 2026-02-05), under the CAISI AI Agent
Standards Initiative.
**Channel:** `AI-Identity@nist.gov` (NCCoE project mailbox).
**⚠️ Caveat:** the formal comment window closed **2026-04-02**. Send as a *supplemental*
contribution and **verify on the project page first** whether late/supplemental input is
accepted: https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
A Gmail draft is staged (subject prefixed "Supplemental comment"). Why bother: NCCoE poses as
*open questions* exactly what EP answers — getting on record positions EP at the standard-setting
table for the project phase.

---

**Re: Supplemental comment — "Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization" (NCCoE / CAISI AI Agent Standards Initiative)**

To the NCCoE AI Agent Identity and Authorization team,

Thank you for the concept paper. We write to contribute a concrete, open primitive aimed directly at three questions you raise: how an agent proves its authority to perform a specific action; how agent identity is bound to human identity for human-in-the-loop authorizations; and how non-repudiation can bind an action back to a human authorization in a tamper-proof, verifiable manner.

We are EMILIA Protocol, an open standards effort (Apache-2.0, published as IETF Internet-Drafts). We are pre-revenue with no production deployment yet; we offer the following as engineering contributions to a shared problem, not as a product pitch.

**Proving authority for a specific action.** Our core construct is an *authorization receipt* (draft-schrock-ep-authorization-receipts). A named human signs the *exact* action — not a session, not a scope — on their own device using a WebAuthn/Class-A authenticator. The receipt is self-contained: anyone can verify it offline, with no account and no trust in the operator who produced it. Alter one byte of the authorized action and verification fails. This directly answers "prove authority to perform a specific action," and does so without a phone-home dependency.

**Binding agent identity to human identity.** A signature proves control of a key, not the identity of a person — the gap the paper implicitly flags. We address it with an *identity-binding profile* that binds the approver's key to a real-world named human, so a verified receipt attests "this named person authorized this action," not merely "some key signed."

**Multi-party human-in-the-loop.** EP-QUORUM (draft-schrock-ep-quorum) expresses M-of-N approval over *distinct* humans — a cryptographic two-person rule for high-consequence agent actions.

**Composing the full authorization story.** EP-AEC (Authorization Evidence Chain) composes delegation, policy-permit, and human-authorization receipts into a single artifact that yields an offline SATISFIED/UNSATISFIED evidence verdict — letting a verifier reconstruct the complete chain from "this human authorized" through "this policy permitted" to "this agent acted." The executor makes the separate authorization decision.

**Long-term non-repudiation.** EP-EVIDENCE-RECORD provides RFC 4998-style, crypto-agile long-term retention, so receipts remain verifiable as algorithms age — relevant to audit and retention obligations long after an action occurs.

**Interoperability and assurance.** We maintain JavaScript, Python, and Go reference verifiers that agree on a public conformance suite, plus machine-checked TLA+/Alloy models of the core protocols. We treat that as a cross-language consistency check, not a clean-room independent-implementation claim. We consider cross-verifier agreement and formal models prerequisites for any primitive proposed as a standard.

**Standards alignment.** The work maps to the NIST AI RMF and is relevant to EU AI Act Article 14 (human oversight). It is complementary to the identity standards the paper considers (OAuth, OIDC, SPIFFE/SPIRE): those establish *who/what an agent is*; authorization receipts establish *that a specific human authorized a specific act, verifiably and after the fact.*

We would welcome the opportunity to contribute reference vectors or implementation feedback to any resulting NCCoE project, and to make our drafts and conformance suite available to the community.

Respectfully,
Iman Schrock · EMILIA Protocol · team@emiliaprotocol.ai
