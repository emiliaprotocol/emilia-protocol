# EMILIA Protocol — Investor Narrative

## The problem

AI agents now install software, route work to external tools, accept delegated authority from humans, and transact with machine counterparties. Every one of these actions requires a trust decision. Today, every platform makes that decision using private heuristics, closed allowlists, or ad hoc blocklists — silently, inconsistently, and with no recourse when the decision is wrong. There is no portable, neutral infrastructure for evaluating whether a counterparty should be trusted for a given task in a given context.

## What EP does

EMILIA Protocol is an open protocol for making, explaining, challenging, and verifying trust decisions about agents, software, and machine counterparties. Before an agent installs software, connects to a tool, accepts delegated authority, or transacts with a counterparty, EP returns a structured trust decision — with reasons and an appeal path.

MCP tells agents how to use tools. EP tells them whether they should.

## Why now

MCP has crossed 10,000 public servers. It has been adopted by ChatGPT, Cursor, Gemini, and VS Code, and donated to the Linux Foundation. Every host running MCP servers needs trust evaluation before connecting agents to tools. NIST is actively scoping accountability and explainability requirements for agentic AI systems. The infrastructure gap is operational and immediate — and EP is among the first open implementations focused explicitly on trust decisions, recourse, and portable evaluation for agent systems.

## The 3-layer architecture

EP is designed in three layers. This matters because it keeps the adoptable core small while allowing the ecosystem and business to grow independently.

### Core (the standard)

Three objects. That is the entire required surface:

- **Trust Receipt** — a portable record of an observed event relevant to trust (subject, outcome, provenance, cryptographic integrity)
- **Trust Profile** — a standardized summary of an entity's observed trust state (confidence, evidence level, behavioral rates, dispute history)
- **Trust Decision** — a policy-evaluated result for a specific action and context (allow / review / deny, with reasons, evidence sufficiency, and appeal path)

If a third party can implement these three objects and interoperate, EP has a real standard.

### Extensions (important, but optional)

Each extension adds operational value without inflating the core:

- Disputes and appeals lifecycle
- Delegation and attribution chains
- Domain-specific scoring
- Zero-knowledge trust proofs
- Auto-receipt generation from tool calls
- Software install preflight adapters
- Identity continuity and anti-whitewashing

### Product surfaces (not part of the standard)

- Hosted trust APIs
- Explorer and registry views
- Operator dashboards
- Managed adjudication workflows
- Enterprise policy management consoles
- Analytics and monitoring

This maps directly to the adoption path: **standard adoption drives ecosystem growth, ecosystem growth drives monetization.**

## First three wedges

### 1. Install preflight

The most immediate use case. Before an agent connects to an MCP server, installs a package, or activates a plugin, EP evaluates the entity and returns a trust decision. Every serious agent host needs this. The question is whether each rebuilds it privately or adopts a shared standard.

### 2. Delegation assurance

When a human delegates authority to an agent, and that agent acts on their behalf — routing work, approving actions, invoking tools — there must be a verifiable record of who authorized what. EP's attribution chain (Principal to Agent to Tool) produces that record, with a delegation judgment computed from outcomes. This is not optional for enterprises deploying agents at scale.

### 3. ZK attestation for regulated counterparties

Healthcare providers, legal firms, and financial institutions cannot expose transaction histories or counterparty relationships to verify trustworthiness. EP's zero-knowledge proof system lets regulated entities prove they meet trust thresholds in a given domain without revealing the evidence behind them. The moment EP becomes the proof layer for sensitive industries, it becomes required infrastructure for those sectors.

## The compounding moat

The defensible asset is the ledger.

Every receipt that flows through EP — whether submitted manually, generated automatically from tool calls, or anchored through a host adapter — makes the trust graph more accurate. The graph is not a snapshot. It is a continuously compounding behavioral record. Every entity that participates makes every other entity's trust profile more meaningful, because trust is evaluated relative to the graph's voucher network, not in isolation.

Every ZK proof issued makes EP harder to replace in regulated environments. Every delegation record creates institutional dependency on EP's attribution chain. Every dispute resolved through the adjudication system deepens the operational commitment.

The network effect is not social. It is structural. The trust graph gets harder to replicate the longer it runs.

## Category logic

This follows the same pattern that made foundational infrastructure layers valuable:

- **HTTPS** became the trust baseline for web transport
- **FICO** became the trust baseline for credit allocation
- **EP** targets the trust baseline for machine-mediated systems — but with portability, openness, and appealability rather than institutional capture

The category does not yet exist. The company that defines it operates the standard.

## Business Model

The protocol is free. The control plane is paid.

- **Free:** EP Core specification, reference implementation, conformance fixtures, self-hosted deployment path
- **Paid:** Hosted trust decision API, enterprise policy management, private receipt storage and trust graphs, managed adjudication workflows, compliance logging/analytics/audit exports, identity binding/delegation governance/proof issuance at scale, SLAs/support/private deployment

**Why it works:** Open standards expand adoption. Managed control planes capture operational spend.

The business is not in selling the spec. It is in becoming the operating company around the standard:

- **Hosted trust APIs** — managed evaluation, receipt submission, and decision endpoints for teams that do not want to run their own infrastructure
- **Operator services** — onboarding, adapter configuration, policy authoring, and integration support for platforms adopting EP
- **Enterprise policy management** — custom trust policies, compliance mapping, audit tooling, and role-based access for organizations with regulatory requirements
- **Adjudication tooling** — managed dispute resolution workflows, evidence review interfaces, and escalation paths for high-stakes trust decisions

All of these are built on top of the open standard. The standard drives adoption. The services capture value.

## The First Revenue Wedge

The first product is not "universal trust." It is install and connect preflight for agent tooling. Every serious enterprise agent deployment must answer: Should this MCP server be allowed? Should this package be installed? Should this delegated action be allowed?

## Why EP Can Win Economically

Moat = portable decision interfaces + durable dispute/appeal history + attribution records + privacy-preserving verification + policy integrations into production workflows.

## What makes EP defensible

Three things, operating together:

**Open standard.** EP is Apache 2.0. The core spec is deliberately small. This is not generosity — it is strategy. An open standard attracts adoption that a proprietary system cannot. The operating company benefits from every adopter because the graph compounds.

**Constitutional guarantee.** EP enforces a structural principle: trust must never be more powerful than appeal. Any adverse trust effect must be explainable, challengeable, reviewable, and reversible when wrong. This is not philosophy. It is the governance constraint that prevents EP from becoming another captured platform trust system — and it is what makes neutrality credible to adopters who have been burned by platform lock-in before.

**Network effects from the ledger.** Every receipt, every proof, every delegation record, every resolved dispute deepens the trust graph. The graph cannot be forked without losing its history. Competitors can copy the spec. They cannot copy the accumulated behavioral record.

**EP Commit — mandatory pre-action authorization.** EP Commit turns advisory trust into mandatory pre-action authorization. A signed authorization token proves that a machine action was evaluated under policy before proceeding. Relying systems can require an EP Commit before allowing install, connect, delegate, or transact actions. This is the single strongest monetization primitive: every consequential agent action that requires a commit token is a billable trust decision. Advisory scores are optional. Signed authorization is enforceable.

## Current state

Sober accounting of where EP stands:

- 29 MCP tools implemented across trust evaluation, receipt management, disputes, delegation, ZK proofs, install preflight, and EP Commit
- 670 tests passing across the conformance suite
- Reference implementation live and open-source
- REST API and MCP server surfaces operational
- Host adapters demonstrated for MCP servers and software install preflight
- Core spec, extension boundaries, and product surfaces clearly separated

EP is early. The protocol works. The standard is defined. The ecosystem does not yet exist at scale — that is the opportunity.

## The ask

EMILIA Protocol is an infrastructure company in the making. The trust layer for agents, software, and machine counterparties is a missing piece of the agentic stack, and the window to define it is open now.

We are raising to fund standard adoption, ecosystem development, and the first hosted operator services — to become the operating company behind the trust layer that agent systems require.

---

*emiliaprotocol.ai | github.com/emiliaprotocol/emilia-protocol | Apache 2.0*
