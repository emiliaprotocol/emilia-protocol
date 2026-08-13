# Product Marketing Context

*Last updated: 2026-08-12*

## Product Overview

**Core line:** Authority for autonomous work.

**One-liner:** EMILIA is the authority control plane that gives autonomous software a customer-owned, finite operating mandate and enforces it at the moment consequential work reaches a real system.

**What it does:** Humans and institutions define the mission, limits, evidence rules, trust roots, expiry, and exception path. Agents work unattended while each consequential unit of work remains inside that mandate. EMILIA Gate sits immediately before a system that can mutate money, code, permissions, regulated records, infrastructure, energy, or physical state. Missing, stale, or insufficient authority produces a closed refusal and an action-bound evidence challenge. On covered shared-durable paths, Gate permits one admitted provider attempt per authorization instance and preserves portable evidence, including authenticated uncertainty when the provider outcome cannot be established.

**Product architecture:**

| Surface | Role | Commercial status |
| --- | --- | --- |
| **EMILIA Authority Brain / Authority Map** | Free local product experience that discovers visible agent-action surfaces, proposes consequence classifications, names blind spots, and routes the owner to protect one action | Apache-2.0 acquisition surface; scanner proposes and never claims enforcement |
| **EMILIA Gate** | Commercial enforcement product at the executor or system-of-record boundary | Primary product |
| **EMILIA Protocol** | Open verification and evidence substrate: formats, exact-action binding, verifier, conformance, and interoperability | Apache-2.0 public infrastructure |
| **EMILIA Approver** | Native apps and embeddable SDKs that capture a device-bound human decision over the exact action | Included capture surface for Gate deployments |
| **EMILIA Assurance Plane** | Managed verification, re-performance, conformance reporting, deployment evidence, reliance packets, and evidence operations | Paid service layer; not an audit opinion or accredited certification |

**Product category:** Authority control plane for autonomous work.

**Product metaphor:** EMILIA Gate is the consequence firewall at the executor boundary. This describes the enforcement product, not the company category.

**Operating posture:** AI workers need authority, not constant supervision. A human click is one possible authority source, not the default execution model. Customers may install a durable, bounded mandate and allow unattended work inside it. Fresh human or institutional authority is required only when the customer requires per-occurrence review or when authority is missing, expired, widened, renewed, or used to authorize a separate remedy.

**Product type:** Open-core security infrastructure with managed cloud, BYOC, enterprise integrations, and assurance services.

**Business model:**

- The open verifier, protocol formats, conformance vectors, and interoperability materials remain reproducible and Apache-2.0.
- The paid Gate surface includes customer-operated or EMILIA-managed enforcement, policy, trust and revocation operations, integrations, durable consumption, evidence retention, deployment operations, support, SLA, and separately contracted warranty.
- In either deployment mode, the customer remains the relying party and controls authority, policy, trust roots, provider credentials, acceptance rules, and portable evidence. Managed operation does not transfer authority ownership to EMILIA.
- The paid Assurance Plane includes verification and re-performance services, signed scoped result artifacts, conformance reports, deployment-evidence packages, evidence operations, and partner workflows.
- Any future certification mark depends on independent governance, scoped assessor authority, and external participation. EMILIA does not currently operate a public certification scheme and must not present itself as an auditor or accredited certifier.

## Message Hierarchy

Use this order in product, repository, sales, and machine-facing explanations:

1. **Outcome:** Put autonomous software to work while the customer keeps authority.
2. **Mandate:** The customer defines mission, limits, evidence, trust roots, expiry, and exceptions once; agents work unattended inside those bounds.
3. **Enforcement:** Gate mediates consequential work at the executor boundary, challenges for exact evidence, verifies, reserves before provider entry, admits one covered provider attempt, and records the result without inventing certainty.
4. **Neutrality:** EMILIA Protocol makes the evidence independently verifiable under the customer's own pinned rules and keys.
5. **Exception ceremony:** EMILIA Approver can capture a device-bound decision when policy requires a person or the requested work exceeds the standing mandate.
6. **Operational proof:** EMILIA Assurance Plane re-performs decisions and produces scoped evidence for auditors, insurers, regulators, and customers.
7. **Engineering proof:** Executable security claims, formal models, adversarial conformance, same-team language ports, and time-pinned external implementation evidence.

Do not lead a buyer or a language model with the draft portfolio, formal-method inventory, CAID, AEC, or a generic "trust architecture." Those prove the product after the problem and enforcement outcome are understood.

## Target Audience

### Free adoption wedge: Authority Brain — discover, map, protect, and prove

**Target companies:** Teams deploying agents that can call administrative, production, financial, data, or infrastructure tools.

**Primary users:** AI platform engineers, security engineers, MCP server maintainers, and developer-tool teams.

**Job to be done:** Run the local Authority Brain to discover the declared actions the scanner can actually see, review its proposed Authority Map and blind spots, place a deny-by-default check in front of one consequential call, and preserve a factual record of the completed local setup without replacing the agent framework or joining a standards process.

**Adoption promise:** `npx @emilia-protocol/scan brain ./tools.json` creates a self-contained local Authority Map without an account, upload, telemetry, or remote asset. The scan launches no configured server and makes no prevention claim. The owner reviews the proposal; the protect step requires action-bound evidence for one selected tool; and the optional factual handoff reports completed local checks without claiming certification, deployment security, or complete mediation.

**Commercial role:** Public distribution and proof of demand. The conversion event is a buyer-selected $25K protected-workflow pilot, not a vanity scan or certification sale.

### GitHub-native entry experiment: protect production deployment

**Decision:** Use GitHub as a distribution and integration rail for Gate, not as a new company category and not as an excuse to build a general agent marketplace. EMILIA is not itself a GitHub Agent App. It is the authority layer outside coding agents, so the same control can govern work proposed by Copilot, an Agent App, a third-party coding agent, or a person.

**Free surface:** A narrowly scoped GitHub Action may map agent-reachable workflows, privileged permissions, protected environments, and visible bypass paths. It is an Authority Brain distribution surface. Running the Action does not establish complete mediation and must not be marketed as preventive enforcement. Repository use of an Action is also not a GitHub App installation and does not count toward GitHub's current 100-install threshold for publishing a paid App plan.

**Enforcement surface:** The candidate GitHub App is a custom deployment-protection rule for one production environment. GitHub pauses the referenced deployment job and withholds environment secrets while Gate evaluates a customer-owned mandate over the exact repository, environment, commit SHA, ref, workflow run, and other closed material fields. Gate then approves or rejects the deployment through GitHub's callback, consumes admitted authority once, and retains portable evidence under customer-pinned rules.

**Authority source:** A repository file such as `.github/emilia-mandate.yml` may propose selectors or display customer-reviewed configuration, but it is not authority merely because it is present in the repository. Any field an agent or ordinary contributor can modify is untrusted input. Enforce only a customer-signed or externally pinned mandate and protect changes to the workflow, ruleset, environment, App configuration, approver directory, and mandate digest under a separately controlled administrative path.

**Human-decision posture:** Do not require a hardware-key tap for every deployment by default. A standing, finite customer mandate may authorize unattended deployments inside its bounds. Fresh device-bound human or institutional authority is required only when the customer's policy requires per-occurrence review or the action is missing, stale, expired, wider, or otherwise outside the mandate. TOTP is not an equivalent fallback because it does not bind the approver to the exact action bytes.

**Initial action coverage:** The first supported consequence is a workflow job entering a protected production environment. A protected merge can be a later profile when an App-sourced required check and bypass controls provide the boundary. Release publication, secret rotation, repository-permission changes, workflow-file mutation, and dependency approval do not share one generic pre-action veto; each needs a separately proven GitHub control or credential-owning executor path before it is advertised as blocked by Gate.

**Required boundary:** The deployment is protected only when every covered production job names the protected GitHub environment, the EMILIA App is enabled on that environment, bypass is disabled, workflow and ruleset administration are separately controlled, and no alternate credential or deployment path avoids the boundary. Direct cloud deploys, unprotected workflows, mutable workflow definitions, or administrators allowed to bypass remain explicit exclusions until separately mediated.

**Platform posture:** GitHub's Agent Apps channel is currently a partner preview, but EMILIA does not need Agent App status. A normal GitHub App can implement a deployment-protection rule. The protection-rule feature is itself in public preview, and private or internal repository use requires GitHub Enterprise under the current GitHub documentation; both are product and go-to-market constraints, not footnotes.

**Validation sequence:**

1. Reuse the existing GitHub allowance, consequence-control, custody, and evidence machinery to build one deployment-protection-rule prototype; do not claim the native App exists before that path is runnable.
2. Dogfood it on an EMILIA-controlled public repository and demonstrate authorized deployment, stale or mismatched evidence refusal, replay refusal, denied bypass configuration, and `INDETERMINATE` handling without blind retry.
3. Obtain ten external installations that enable the rule on at least one real environment, three organizations that use it repeatedly, and one buyer-funded protected-deployment pilot.
4. If the Action shows demand, release a genuinely useful free GitHub App so App installations—not Action invocations—can test the path toward GitHub's current 100-install threshold for a paid Marketplace plan. Treat the threshold as a distribution requirement, not as proof that 100 installations are easy or as a company milestone by itself.
5. Change the deck's first paid wedge only after the GitHub path produces stronger buyer evidence than the named payer workflow. Until then, GitHub is the developer-distribution and technical-validation lane; payer adverse determinations remain the stated paid wedge.

**Long-term option, not current claim:** Scoped conformance and customer-authorized aggregate evidence may eventually help buyers compare an agent in a named workflow and environment. EMILIA does not passively centralize customer receipts, publish a universal agent reliability score, certify agents, or operate an investment marketplace. Any future financing product belongs to a regulated platform; EMILIA may supply authority and evidence infrastructure to that platform.

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

**Core problem:** An AI agent can hold valid credentials and still attempt work outside the mission, limits, evidence rules, or exception path its owner intended. IAM proves who or what has access. It does not define the job, bind a consequential unit of work to the mandate that authorized it, or preserve durable authority state after the agent process disappears.

**Why alternatives fall short:**

- IAM, OAuth, and workload identity establish identity or delegated scope, not exact-action human authorization.
- Prompt filters and AI firewalls inspect model inputs and outputs, not the final executor-side mutation.
- Workflow approval tools often retain operator-controlled records that are difficult for an outside party to verify independently.
- Logs describe what the operator says occurred after the fact; they do not necessarily prevent the action.
- Closed vendor attestations make the customer trust the same party that operates the control.
- A protocol specification alone does not provide complete mediation, deployment operations, or a managed evidence lifecycle.

**Cost of the problem:** Delayed agent deployment, manual review overhead, weak incident reconstruction, disputed responsibility, failed control testing, and consequential actions that cannot be defended later.

**Emotional tension:** "The agent had access, but was this work actually inside its mandate—and can we prove that without trusting the agent's own log?"

## Differentiation

**Key differentiators:**

- Executor-side mediation before mutation, with a closed refusal when evidence is absent or insufficient.
- Exact-action binding across approval, policy, authority, request custody, provider evidence, observed-effect evidence, and remedy without collapsing those claims.
- One-time consumption and explicit indeterminate-effect handling.
- Customer-pinned keys, policies, directories, registries, and acceptance profiles.
- Open, offline verification that does not require an EMILIA callback.
- Device-bound human capture through Approver apps and SDKs.
- Reproducible assurance packages and re-performance that do not trust the runtime's stated verdict.
- Narrow conformance artifacts whose scope and limitations travel with the result.

**Why this is better:** A buyer can deploy a preventive product now, retain control of its trust roots, and later prove what the product did without asking the vendor to validate its own story.

**Defensibility:** The product moat is installed complete-mediation integrations, durable authority and custody operations, provider-evidence profiles, customer workflow configuration, assurance procedures, support, and warranty. The acceptance moat grows only when relying parties accept or require compatible evidence; receipt volume by itself is not a network effect. The neutrality moat is the open substrate, external implementation evidence, partner integrations, and reproducible verdict computation. Product success must not turn the Protocol into a vendor-controlled trust root.

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

- "AI workers need authority, not constant supervision."
- "Set the mandate once. Let the agent work."
- "Put AI to work. Keep authority."
- "The scanner maps work. The owner sets authority. Gate enforces."
- "Authority infrastructure for autonomous work."
- "The agent is ephemeral. Authority state survives."
- "No valid authority, no consequential mutation."
- "No valid licensed-review evidence, no adverse determination."
- "A policy decision is not the same as human authorization."
- "Complete mediation at the system of record."
- "EMILIA operates the control; the customer controls the authority, credentials, and evidence."

**Words to use:** authority control plane, autonomous work, machine workforce, operating mandate, unit of work, consequence firewall, exact action, executor boundary, system of record, complete mediation, customer-pinned trust, evidence challenge, one-time consumption, re-performance, scoped conformance, independent verification.

**Words to avoid:** universal trust, AI safety solved, impossible to bypass, proof of comprehension, proof an external effect occurred from a local log, automatic rollback, fully independent implementations, certified deployment, compliant by default, guaranteed legality, statute-mandated EMILIA, Visa network for AI actions.

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

**Primary business goal:** Land one leverage-bearing, production-adjacent deployment that installs a customer-owned operating mandate and controls a real consequential workflow.

**Adoption goal:** Make local Authority Brain → review the Authority Map → protect one tool → factual handoff the fastest free path into the product.

**Revenue goal:** Sell a payer or utilization-management pilot that enforces and evidences licensed review before an adverse medical-necessity determination.

**Primary conversion actions:**

- Developer: scan locally, protect one consequential MCP or HTTP action, and optionally publish a factual Agent Record.
- Enterprise: scope one executor-side Gate pilot.
- Assurer: re-perform one evidence package under independently pinned keys.
