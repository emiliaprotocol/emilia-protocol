# EP Positioning Reference

**Status: Canonical**
**Last updated: March 2026**
**Owner: Core team**

This document is the source of truth for all EP positioning. When positioning drifts across README files, pitch decks, demo scripts, standards submissions, or investor materials — fix it here first, then propagate. Do not patch individual documents without updating this one.

---

## The One-Line Truth

Use this in every document, every audience, every context:

> "EP enforces trust before high-risk action."

This is the canonical line. Everything else is a derivative.

---

## Supporting line for AI / agent contexts

> "MCP tells agents how to use tools. EP tells systems whether a high-risk action should be allowed to proceed."

Use this when AI tooling is the context. Do not let it replace the canonical line.

---

## Technical positioning

> "EP is a protocol-grade trust substrate that binds actor identity, authority, policy, and exact action context into a replay-resistant, one-time authorization flow."

Use this with:
- enterprise architects
- security teams
- standards bodies
- sophisticated buyers

---

## The Three-Layer Architecture (Core / Extensions / Product Surfaces)

**This is the first structural concept. Lead with it in every architecture discussion, every standards submission, and every technical overview.**

EP is a 3-layer system. The core is deliberately small — three objects that any host can implement. Everything else is an optional extension or a product surface.

- **EP Core** — The interoperable standard. Three required objects:
  - **Trust Receipt** — a portable record of an observed event relevant to trust (what happened)
  - **Trust Profile** — a standardized summary of observable trust state (what is known)
  - **Trust Decision** — a policy-evaluated result with reasons and appeal path (what to do now)
  - Also includes: scoring model, policy evaluation, entity identity, Sybil resistance, conformance requirements

- **EP Extensions** — Important but optional capabilities that build on the core:
  - Disputes and appeals (full lifecycle, trust-graph adjudication, voucher-based resolution)
  - Delegation and attribution chain (Principal → Agent → Tool accountability)
  - Commitment proofs (privacy-preserving trust verification for regulated industries)
  - Auto-receipt generation (passive behavioral data capture from MCP tool calls)
  - Domain-specific scoring (vertical-specific behavioral weights)
  - Install preflight adapters (platform-specific adapters for MCP servers, npm, GitHub Apps)
  - EP Commit (signed pre-action authorization tokens — scores are optional, signed authorization is enforceable)

- **EP Product Surfaces** — Reference implementations and operator tools. Not part of the standard:
  - Explorer, leaderboards, registry views
  - Operator dashboards and managed adjudication workflows
  - Hosted trust APIs, analytics, enterprise policy management

**The test:** a skeptical reader should be able to answer in 30 seconds what is Core vs Extension vs Product. Core = the minimum interoperable standard. Extensions = advanced features you opt into. Product Surfaces = tools and UIs built on top, not governed by the spec.

**Why this matters for positioning:** When critics say "EP is too big," point to the core — three objects, one conformance suite. When adopters say "EP doesn't cover X," point to extensions. When competitors say "EP is just a product," point to the spec/extension/product separation.

---

## What EP Is

EP is an open protocol for trust decisions, not a universal reputation score.

Three bullets. Use these three and only these three when asked to describe EP briefly.

- **A trust protocol** — EP answers whether a counterparty, software component, or machine actor should be trusted enough for a given context and policy. Not a number. A structured profile with confidence levels, behavioral rates, provenance composition, dispute history, and domain-specific scores.

- **A due-process system** — Every trust decision is contestable. Disputes trigger a 48-hour adjudication window, resolved by the trust graph's voucher network — not by operators. Constitutional principle: trust must never be more powerful than appeal.

- **A behavioral ledger** — Auto-receipt generation turns every MCP tool call into a trust signal. The graph compounds continuously. Every agent interaction produces verifiable behavioral evidence. Trust data accumulates from day one without developer instrumentation.

---

## What EP Is Not

State these proactively. Do not wait to be asked.

**EP is not a reputation or social-credit system.** Trust profiles are computed from behavioral receipts — append-only, hash-chained transaction records. There is no holistic social judgment, no platform-controlled ranking, no subjective quality assessment. The protocol evaluates behavior against explicit policy criteria, not social standing.

**EP is not binary.** Binary trust systems fail at the edges — they are gamed at the boundary and useless in novel contexts. EP is probabilistic and policy-shaped. A trust profile produces confidence levels (provisional, emerging, confident, established), not a green or red light.

**EP is not controlled by a single operator.** The protocol is open-source (Apache 2.0). The constitutional principle — trust must never be more powerful than appeal — is baked into the spec, not enforced by company policy. No operator, including the team that built EP, can override a legitimate appeal through administrative action alone.

**EP is not surveillance.** Commitment proofs allow entities to prove they meet trust thresholds in a given domain without revealing counterparties, receipt history, or transaction details. Auto-receipt generation requires explicit opt-in. EP receipts contain no PHI, no PII — trust profiles are computed from transaction metadata only.

**EP is not the next MCP.** This framing will come up. Reject it explicitly. EP does not define how agents connect to tools, communicate with each other, or execute transactions. Those are MCP, A2A, and ACP problems. EP is the layer those systems need to answer the question none of them answer: should this connection happen?

---

## The Winning Frame

**The frame is not "be the next MCP." It is "be the trust protocol that every serious MCP deployment eventually needs."**

MCP is infrastructure. EP complements it. As MCP deployments grow in scope — more tools, more servers, more sensitive contexts — the question of whether any given MCP server should be trusted in any given environment becomes unavoidable. Enterprises deploying MCP in production will need preflight. Regulated industries will need privacy-preserving proof attestation. Any system with automated agents taking consequential actions will need attribution chains and appeals.

EP does not compete with MCP for adoption. It rides MCP's growth curve and captures the trust protocol role that MCP was not designed to provide.

Position EP to MCP builders as: "You've built a great server. Here's how enterprises will trust it enough to actually deploy it."

Position EP to enterprises as: "Your agents are using MCP. Here's how you know which servers are safe enough for your environment, and who is accountable when something goes wrong."

---

## The Beachhead

Do not launch as "universal trust for everything." That is a thesis, not a product. The beachhead is narrow, concrete, and high-frequency.

**Wedge 1 — MCP server / software install preflight** (primary wedge)

Every MCP server installation is a trust decision. EP provides a policy-evaluable preflight check: does this server meet the trust threshold for this context, host, data sensitivity, and tool scope? The output is structured (allow / review / deny), explainable (policy reasons surfaced), and repeatable. This is the highest-frequency, highest-value trust signal event EP can capture. It is also the wedge that most directly answers "what does EP do?" with a concrete demonstration.

**Wedge 2 — Delegated action assurance**

As agents take autonomous actions — making purchases, modifying repositories, sending communications — the question of authorization becomes critical. EP's attribution chain (Principal→Agent→Tool) creates a verified accountability record for every delegated action. Delegation judgment scoring produces a graded human accountability record (excellent / good / fair / poor). Enterprises deploying agents will need this. Regulators will eventually require it.

**Wedge 3 — Privacy-preserving commitment proofs for regulated industries**

Healthcare, legal, and financial institutions cannot participate in trust systems that require exposing transaction histories or counterparty relationships. EP's commitment proof layer (HMAC-SHA256 + Merkle commitment, with full zk-SNARK on roadmap) allows regulated entities to prove they meet trust thresholds in a given domain without revealing the evidence behind them. This is the wedge that makes EP required infrastructure for the sectors that handle the most sensitive agentic workflows.

**Later wedges** (do not lead with these):
- Agentic commerce receipts
- Universal behavioral memory across agent deployments
- Cross-ecosystem trust portability

---

## The Bootstrap Answer

The cold-start problem for trust networks is real. Address it directly rather than waiting to be asked.

**EP's answer has four components:**

1. **Auto-receipt generation creates trust signals from day one.** Every MCP tool call automatically generates a behavioral receipt. Developers do not need to instrument anything. Every agent interaction produces data. The graph does not wait for manual submissions.

2. **Bilateral confirmations upgrade unilateral receipts to verified.** A self-attested receipt carries lower weight. A bilaterally confirmed receipt carries higher weight. The protocol creates an incentive structure where participants benefit from confirming each other's receipts — which is exactly the network behavior that builds the graph.

3. **Install preflight creates high-frequency, high-value events.** Every software installation is a trust evaluation event. This is not a low-frequency signal like annual reviews or infrequent transactions. It happens every time a developer adds a new MCP server. High frequency means faster graph growth and earlier confidence levels.

4. **Operator applications seed the graph with credible participants.** The pilot program enrolls operators with existing user bases. Their participation creates a credible starting population of trust graph participants, which reduces the time to meaningful network effects.

---

## Three-Label System

Use these labels everywhere — in READMEs, documentation, demo scripts, and investor materials. Never describe a roadmap feature as shipped. Never undersell a live feature as a prototype.

**[Live]** — Shipped, deployed, accessible via API or `npx`.
**[Pilot]** — Available with operator enrollment or limited access.
**[Roadmap]** — Planned, not yet shipped.

### What Is Live

- 29 MCP tools, 4 resources, 3 prompts
- Trust profiles with 4 policy types: `strict`, `standard`, `permissive`, `discovery`
- Install preflight for MCP servers, GitHub Apps, npm packages, and Chrome extensions
- Disputes and appeals with constitutional due process (48-hour window, voucher voting)
- Auto-receipt generation (opt-in, privacy-preserving)
- Trust-graph dispute adjudication (receipt weight: 0.3x active dispute, 0.0x upheld, 1.0x dismissed)
- Attribution chain: Principal→Agent→Tool (migration 026)
- Delegation judgment scoring: 4 grades (excellent / good / fair / poor)
- Commitment proofs: HMAC-SHA256 + Merkle commitment (commitment-based; full zk-SNARK on roadmap)
- Domain-specific scoring: 7 domains
- Trust gate: pre-action canonical check
- Identity continuity: EP-IX (anti-whitewashing)
- TypeScript SDK: 25 methods
- Python SDK: 21 methods
- 670 automated checks across 28 test files (JS + Python conformance, adversarial, end-to-end, conformance replay)
- Protocol Standard v1.0 (17 sections)

### What Is Pilot

- Operator applications and registry
- Managed adjudication workflows

### What Is Roadmap

- Oracle verification (Phase 3 provenance)
- GraphQL API
- Mobile SDK
- Webhook receipt streaming
- Full zk-SNARK (currently ZK-lite commitment-based)

---

## Audience-Specific Framing

### For MCP Builders

**Lead with:** Install preflight and trust profiles for MCP servers.

**Core message:** You have built a server. Enterprises will not deploy it without a way to answer trust questions specific to their context. EP is how your server gets installed in production environments that have security and compliance requirements. An EP trust profile is the difference between "this server exists" and "this server meets our policy for this workspace."

**What resonates:** The install preflight demo. Run it live if possible. The concrete output — allow / review / deny, with policy reasons — is more persuasive than any abstract positioning.

**Do not say:** "EP evaluates your trustworthiness." This feels like a judgment. Say instead: "EP gives your server a verifiable behavioral record that evaluating agents can query."

---

### For Enterprise and Regulated Industries

**Lead with:** Attribution chains, delegation judgment scoring, and privacy-preserving commitment proofs.

**Core message:** Your agents are making consequential decisions. When something goes wrong — a purchase, a repository modification, a communication sent — you need a verifiable record of who authorized what. EP's Principal→Agent→Tool attribution chain produces that record. EP's commitment proofs let you participate in trust networks without exposing confidential operational data.

**What resonates:** The accountability question. "When your agent does something wrong, can you prove what you authorized it to do?" Most enterprise teams do not have a good answer. EP provides one.

**Regulatory angle:** Frame EP as the behavioral audit trail that compliance teams will eventually require. EP builds that record continuously, from the first tool call.

**Do not say:** "Trust scores." Say "trust profiles," "behavioral records," "policy evaluation." Scores feel like social credit. Profiles feel like structured evidence.

---

### For NIST and Standards Bodies

**Lead with:** Open specification, portable trust object model, constitutional due process, and cross-ecosystem composability.

**Core message:** EP is a vendor-neutral, open-source (Apache 2.0) protocol for trust evaluation and appeals across AI agents, software, and machine actors. It directly addresses all three CAISI pillars: industry-led standard development, open-source protocol implementation, and AI agent security and identity. EP is the proposed reference implementation for a Trust Evaluation and Appeals Working Group, not a finished standard imposed for adoption.

**Technical credibility markers to surface:** 670 automated checks, Protocol Standard v1.0 with 17 sections, cross-language conformance verification (JS + Python), commitment proof layer for regulated sector participation, constitutional due process guarantees, adversarial resistance in dispute adjudication.

**Unlike TLS qualifier:** Always pair the SSL/TLS analogy with the probabilistic/contextual/contestable qualifier. Standards audiences will probe the analogy. Volunteering the limitation before they raise it signals technical seriousness.

**Frame the ask:** "Let's build a neutral trust evaluation standard together, starting from a working reference" — not "adopt our product."

---

### For Investors

**Lead with:** Category logic, moat structure, and the compounding nature of the trust graph.

**Core message:** Every foundational internet layer that became indispensable did so by solving trust at the right moment — HTTPS for web transport, FICO for credit allocation. EP is the same category play for machine-mediated systems. The moat is not the algorithm. It is the ledger: the behavioral receipt graph that becomes more accurate and harder to replicate the longer it runs.

**Three compounding moats:**
1. The ledger — every receipt makes every profile more accurate; network effect is structural, not social
2. The privacy-preserving proof layer — regulated industries that rely on EP's commitment proofs cannot migrate to systems that lack them
3. The attribution chain — human principals whose delegation history lives in EP have incentive to continue using EP rather than starting over

**Business model:** Not selling the spec. Operating company around the standard: hosted trust APIs, install preflight services, enterprise policy management, appeals and adjudication tooling, provenance connectors, analytics.

**The number to know:** 35–45% assessed probability of becoming the default trust protocol for agent systems. That is a real number, not a vanity projection.

**What not to lead with:** The technical architecture. Investors want category logic and moat structure first. Architecture is supporting evidence, not the thesis.

---

### For the Developer Community

**Lead with:** What EP does in one tool call, and why trust profiles beat scores.

**Core message:** EP's MCP server puts trust evaluation directly in Claude and any MCP-compatible agent. Developers do not need to build trust infrastructure — they query it. The trust gate is a pre-action canonical check any agent can run before executing a consequential action.

**The shift to make vivid:** Trust profiles, not scores. A single numeric score collapses context, hides reasoning, and cannot be appealed. A trust profile surfaces confidence level, behavioral outcomes, provenance composition, and dispute history. Agents make decisions against explicit policies, not opaque thresholds.

**Open-source angle:** Apache 2.0. EP Core RFC is public. The spec is designed to be implemented independently, not consumed through a single vendor. Invite contribution to the conformance suite.

**What resonates:** The auto-receipt feature. "Every MCP tool call already generates a trust signal. You do not need to do anything." Zero developer friction for the most important capability.

---

## What Not To Say

| Avoid | Use instead | Why |
|---|---|---|
| "Trust attestation" | "Trust evaluation and appeals" | Attestation implies one-way assertion; EP is bidirectional and contestable |
| "Reputation system" | "Trust protocol," "trust system" | Reputation implies social judgment; EP is behavioral and policy-based |
| "Score layer" | "Trust protocol" | Score implies numeric simplification; EP produces structured profiles |
| "Check score" | "View trust profile," "evaluate trust," "run install preflight" | Same reason |
| "Bad score / recover from a bad score" | "Degraded trust," "rebuild trust" | Score language feels punitive and opaque |
| "The next MCP" | Do not use this frame at all | It positions EP as a competitor rather than a complement |
| "Universal trust for everything" | Name the specific wedge | Too abstract to be credible; the beachhead is what's real |
| "Trustworthiness score" | "Trust profile" | Same reason; also feels like social credit |
| "Agent reputation" | "Agent trust profile," "behavioral record" | Reputation has connotations of social standing |
| "Blacklist / whitelist" | "Deny-listed," "approved" | Standard inclusive language; also more precise |
| Unqualified "SSL/TLS" analogy | Always pair with the probabilistic/contestable qualifier | The analogy is useful but technically imprecise without the qualifier |
| "EP evaluates you" | "EP evaluates your behavioral record against a policy" | The former implies judgment of a person; the latter is accurate |

---

## The Competitive Landscape

EP operates in a space with no direct equivalent — which is both the opportunity and the positioning challenge. The question is not "why EP instead of X" — it is "why is there no X yet, and why does EP get there first."

**MCP (Model Context Protocol)** — Not a competitor. EP complements MCP. MCP defines tool connectivity. EP evaluates whether that connectivity should happen in a given context. The winning frame applies here directly: "MCP tells agents how to use tools. EP tells them whether they should." Every serious MCP deployment is an eventual EP customer.

**A2A (Agent-to-Agent Protocol)** — Not a competitor. A2A coordinates agent communication. EP evaluates trust between communicating agents. EP trust context belongs in A2A Agent Cards for routing decisions.

**ACP / UCP / AP2** — Not competitors. These define commerce and payment flows. EP trust proofs attach to ACP payment flows as the "should this transaction happen?" layer. EP is composable with all of them.

**Platform trust systems (Shopify, GitHub, app stores)** — Predecessors, not competitors. Platform-controlled trust systems are captured by design — whoever hosts the trust system controls the ranking. EP's portability and due-process guarantees make platform capture structurally impossible. Position EP as what replaces platform trust lock-in, not what competes with it.

**Ad-hoc agent safety systems** — Early-stage, context-specific, non-portable. The gap EP fills is exactly what these systems cannot provide: a portable, policy-evaluable, contestable trust object that travels with the entity across contexts and systems.

**The honest answer to "why will EP win":** First mover with a working reference implementation, constitutional due process, privacy-preserving commitment proofs for regulated industries, and a compounding behavioral ledger. The trust graph gets harder to replicate the longer it runs. The moat is structural.

---

## Usage Discipline

Different audiences require different language. Match the register to the reader:

- **Standards audiences:** interoperable trust evaluation, adverse-decision review, portability, auditability, privacy-preserving verification
- **Enterprise buyers:** install preflight, delegated action assurance, audit trail, accountability, policy enforcement
- **Investors:** open standard, paid control plane, wedge, moat, adoption tailwind
- **Media/keynotes:** can use the stronger metaphorical language

---

*EMILIA Protocol · emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol · Apache 2.0*
