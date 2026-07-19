# Product Marketing Context

*Last updated: 2026-07-17*

## Product Overview

**Core line:** Protocol proves. Gate prevents.

**One-liner:** EMILIA Gate is the commercial consequence firewall that blocks consequential machine actions until the executor can verify the exact authority and evidence its owner requires.

**What it does:** EMILIA Gate sits immediately before a system that can mutate money, code, permissions, regulated records, infrastructure, energy, or physical state. A missing or insufficient authorization produces a closed refusal and an action-bound evidence challenge. A permitted action executes once and leaves portable evidence that can be checked independently.

**Product architecture:**

| Surface | Role | Commercial status |
| --- | --- | --- |
| **EMILIA Gate** | Commercial enforcement product at the executor or system-of-record boundary | Primary product |
| **EMILIA Protocol** | Open verification and evidence substrate: formats, exact-action binding, verifier, conformance, and interoperability | Apache-2.0 public infrastructure |
| **EMILIA Approver** | Native apps and embeddable SDKs that capture a device-bound human decision over the exact action | Included capture surface for Gate deployments |
| **EMILIA Assurance Plane** | Managed verification, re-performance, conformance reporting, deployment evidence, reliance packets, and evidence operations | Paid service layer; not an audit opinion or accredited certification |

**Product category:** Consequence Firewall for AI agents and other machine actors.

**Product type:** Open-core security infrastructure with managed cloud, BYOC, enterprise integrations, and assurance services.

**Business model:**

- The open verifier, protocol formats, conformance vectors, and interoperability materials remain reproducible and Apache-2.0.
- The paid Gate surface includes managed policy, trust and revocation operations, integrations, durable consumption, evidence retention, deployment operations, support, SLA, and separately contracted warranty.
- The paid Assurance Plane includes verification and re-performance services, signed scoped result artifacts, conformance reports, deployment-evidence packages, evidence operations, and partner workflows.
- Any future certification mark depends on independent governance, scoped assessor authority, and external participation. EMILIA does not currently operate a public certification scheme and must not present itself as an auditor or accredited certifier.

## Message Hierarchy

Use this order in product, repository, sales, and machine-facing explanations:

1. **Outcome:** EMILIA Gate prevents consequential machine actions without verifiable authority.
2. **Mechanism:** It mediates the executor boundary, challenges for exact evidence, verifies, consumes once, and records the result.
3. **Neutrality:** EMILIA Protocol makes the evidence independently verifiable under the customer's own pinned rules and keys.
4. **Human ceremony:** EMILIA Approver captures a device-bound decision over the exact action.
5. **Operational proof:** EMILIA Assurance Plane re-performs decisions and produces scoped evidence for auditors, insurers, regulators, and customers.
6. **Engineering proof:** Executable security claims, formal models, adversarial conformance, same-team language ports, and time-pinned external implementation evidence.

Do not lead a buyer or a language model with the draft portfolio, formal-method inventory, CAID, AEC, or a generic "trust architecture." Those prove the product after the problem and enforcement outcome are understood.

## Target Audience

### Free adoption wedge: privileged MCP tool calls

**Target companies:** Teams deploying agents that can call administrative, production, financial, data, or infrastructure tools.

**Primary users:** AI platform engineers, security engineers, MCP server maintainers, and developer-tool teams.

**Job to be done:** Put a deny-by-default check in front of one consequential tool call without replacing the agent framework or joining a standards process.

**Adoption promise:** A missing receipt returns an action-bound challenge; valid evidence permits the exact call once; replay and tampering are refused.

**Commercial role:** Developer distribution, reference deployments, logos, and integration pull. This is not assumed to be the first high-value revenue wedge.

### First paid wedge: payer adverse medical-necessity determinations

**Target companies:** Health plans, utilization-management vendors, delegated medical groups, and healthcare administrators using AI to support decisions that may deny, delay, or modify care based on medical necessity.

**Decision-makers:** Medical directors, utilization-management leaders, compliance and legal leaders, CISOs, CIOs, and audit or assurance teams.

**Safety rule:** No valid licensed-review evidence, no adverse determination.

**Job to be done:** Demonstrate that the required qualified reviewer evaluated the exact case, criteria version, proposed outcome, and material facts before the adverse determination was issued.

**Fail-closed behavior:** Missing, stale, invalid, unqualified, or mismatched review evidence blocks the adverse determination and routes to the payer's lawful human-review or patient-protective fallback. It does not block medically necessary care.

**Regulatory boundary:** Regulatory requirements can create demand for demonstrable human review, but no law should be described as mandating EMILIA, cryptographic receipts, or this implementation.

### Later expansion

Payments, government disbursement, code and cloud administration, grid operations, and physical action are expansion profiles after a leverage-bearing deployment is established. They demonstrate horizontal applicability; they are not simultaneous opening wedges.

## Personas

| Persona | Cares about | Challenge | Value promised |
| --- | --- | --- | --- |
| AI platform engineer | Fast integration and deterministic behavior | Existing agents can reach privileged tools directly | One MCP or HTTP guard with machine-readable refusal and retry |
| Security architect / CISO | Complete mediation, key ownership, replay resistance, and auditability | Identity and permissions do not prove approval of the exact action | Executor-side enforcement under customer-pinned policy and trust roots |
| Payer medical director | Qualified review and defensible adverse determinations | AI-supported workflows can obscure whether licensed review actually occurred | Exact case-bound licensed-review evidence before an adverse decision |
| Compliance / legal leader | Reproducible evidence and honest scope | Operator-controlled logs are difficult to rely on across boundaries | Portable evidence plus explicit assumptions, limitations, and refusal reasons |
| Auditor / independent assurer | Re-performance rather than management assertion | Runtime reports can repeat the operator's own conclusion | Content-addressed assurance packages and independently pinned re-performance |
| Financial buyer | Deployment risk, integration cost, and accountability | A protocol alone does not operate a production control | Managed Gate, evidence operations, support, SLA, and scoped assurance services |

## Problems And Pain Points

**Core problem:** An AI agent can hold valid credentials and still attempt an action that no accountable person authorized in that exact form. IAM proves who or what has access. It does not prove that the material action about to execute matches a valid approval and may be consumed once.

**Why alternatives fall short:**

- IAM, OAuth, and workload identity establish identity or delegated scope, not exact-action human authorization.
- Prompt filters and AI firewalls inspect model inputs and outputs, not the final executor-side mutation.
- Workflow approval tools often retain operator-controlled records that are difficult for an outside party to verify independently.
- Logs describe what the operator says occurred after the fact; they do not necessarily prevent the action.
- Closed vendor attestations make the customer trust the same party that operates the control.
- A protocol specification alone does not provide complete mediation, deployment operations, or a managed evidence lifecycle.

**Cost of the problem:** Delayed agent deployment, manual review overhead, weak incident reconstruction, disputed responsibility, failed control testing, and consequential actions that cannot be defended later.

**Emotional tension:** "The agent had access, but can we prove anyone approved this exact action before it happened?"

## Differentiation

**Key differentiators:**

- Executor-side mediation before mutation, with a closed refusal when evidence is absent or insufficient.
- Exact-action binding across approval, policy, authority, execution, and evidence.
- One-time consumption and explicit indeterminate-effect handling.
- Customer-pinned keys, policies, directories, registries, and acceptance profiles.
- Open, offline verification that does not require an EMILIA callback.
- Device-bound human capture through Approver apps and SDKs.
- Reproducible assurance packages and re-performance that do not trust the runtime's stated verdict.
- Narrow conformance artifacts whose scope and limitations travel with the result.

**Why this is better:** A buyer can deploy a preventive product now, retain control of its trust roots, and later prove what the product did without asking the vendor to validate its own story.

**Defensibility:** The product moat is the managed enforcement and evidence network, integrations, operational trust configuration, assurance workflows, support, and warranty. The neutrality moat is the open substrate, external implementation evidence, partner integrations, and reproducible verdict computation. Product success must not turn the Protocol into a vendor-controlled trust root.

## Competitive Landscape

**Direct approaches:** Agent gateways and AI security products that intercept tool calls. They may inspect prompts, identities, or policy but do not necessarily provide exact-action, independently verifiable, one-time authorization evidence at the executor.

**Secondary approaches:** IAM, PAM, OAuth, workload identity, policy engines, and approval workflows. These are complementary inputs; they answer different questions and can feed Gate.

**Indirect alternatives:** Manual review, operator-controlled logs, ticket references, and bespoke middleware.

**Standards relationship:** Adjacent identity, delegation, policy, intent, and receipt formats are composition partners, not automatically competitors. EMILIA verifies native artifacts under their own rules, matches material actions under pinned profiles, and keeps machine policy distinct from human authorization.

## Objections

| Objection | Response |
| --- | --- |
| "We can build a check ourselves." | The open specification lets you. Gate is the maintained, hardened enforcement and evidence operation, with conformance, integrations, durable state, and support already assembled. |
| "What stops the agent from going around Gate?" | Only complete mediation does. Gate belongs immediately before the actual mutating system on every supported path. Anything outside that boundary is explicitly not covered. |
| "Why should we trust a startup?" | You do not have to trust EMILIA as the verifier or trust root. Pin your own keys and profiles, run the open verifier, and reproduce the evidence independently. |
| "Is EMILIA a certification body?" | No. Current services verify, re-perform, and package scoped evidence. Audit conclusions belong to the auditor; future certification requires independent governance and authorized assessors. |
| "Does a signature prove the human understood?" | No. It proves the enrolled credential completed the specified ceremony over exact bytes. Comprehension, wisdom, legality, and outcome remain outside the claim. |
| "Does healthcare law require EMILIA?" | No. The paid wedge addresses the operational evidence problem created by requirements for qualified human determination. Never claim a statute mandates EMILIA or cryptographic receipts. |
| "Does Gate make an action safe?" | No. Gate proves and enforces the customer's authorization conditions. It does not judge whether the authorized action is wise, legal, medically correct, or physically successful. |

## Switching Dynamics

**Push:** Agents are reaching consequential tools while existing audit and approval records cannot prove exact pre-execution authority.

**Pull:** One enforcement contract across MCP and HTTP, customer-owned trust, open verification, exact-action mobile approval, and reproducible evidence.

**Habit:** Teams rely on IAM, ticket IDs, manual approval, logs, and after-the-fact review.

**Anxiety:** Deployment complexity, bypass paths, vendor lock-in, operational key management, and fear that a new protocol will require ecosystem-wide adoption.

**Resolution:** Start with one executor-controlled action. Gate protects that rail immediately; ecosystem adoption is not a prerequisite for the first deployment.

## Customer Language

**How buyers describe the problem:**

- "Who approved that action?"
- "What stops the agent from calling the API directly?"
- "Can an auditor verify this without trusting our logs?"
- "Can we prove a licensed reviewer made this determination?"

**Canonical EMILIA language:**

- "Protocol proves. Gate prevents."
- "The Consequence Firewall for machine action."
- "No valid receipt, no mutation."
- "No valid licensed-review evidence, no adverse determination."
- "A policy decision is not the same as human authorization."
- "Complete mediation at the system of record."

**Words to use:** consequence firewall, exact action, executor boundary, system of record, complete mediation, customer-pinned trust, evidence challenge, one-time consumption, re-performance, scoped conformance, independent verification.

**Words to avoid:** universal trust, AI safety solved, impossible to bypass, proof of comprehension, fully independent implementations, certified deployment, compliant by default, guaranteed legality, statute-mandated EMILIA.

## Brand Voice

**Tone:** Calm, sober, technically exact, and commercially direct.

**Style:** Lead with the prevented consequence. Explain the mechanism in plain language. Put standards and formal proof one beat behind the product. State limitations without apology or drama.

**Personality:** Serious, independent, evidence-led, interoperable, and quietly ambitious.

## Proof Points

Quantitative proof changes as the repository evolves. Never copy counts into new marketing prose. Read the generated `AI_CONTEXT.md`, `public/llms-full.txt`, or `public/.well-known/emilia-context.json` and cite the named manifest.

**Current proof classes:**

- Machine-verifiable security claims with hashed evidence, assumptions, and exclusions.
- One composed Tamarin model plus deliberately weakened variants that produce attack traces.
- Public adversarial conformance across same-team JavaScript, Python, and Go ports.
- Time-pinned external Rust implementation and hostility evidence with strict construction status stated separately.
- CF-1 and EG-1 executable enforcement conformance.
- EP-ASSURANCE-PACKAGE-v1, `ep-assure`, external-verifier signed statements, auditor workpapers, underwriter attestations, and reliance packets.
- Native iOS and Android reference apps and SDKs with explicit deployment and platform-attestation boundaries.
- Individual IETF Internet-Drafts, never represented as RFCs or IETF endorsement.

## Goals

**Primary business goal:** Land one leverage-bearing, production-adjacent Gate deployment that controls a real consequential rail.

**Adoption goal:** Make privileged MCP tool-call protection the fastest free path into the product.

**Revenue goal:** Sell a payer or utilization-management pilot that enforces and evidences licensed review before an adverse medical-necessity determination.

**Primary conversion actions:**

- Developer: protect one consequential MCP or HTTP action.
- Enterprise: scope one executor-side Gate pilot.
- Assurer: re-perform one evidence package under independently pinned keys.

