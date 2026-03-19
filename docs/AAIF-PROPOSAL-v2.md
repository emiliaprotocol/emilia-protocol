# EMILIA Protocol — AAIF Working Group Proposal

**Working Title:** Trust Evaluation and Appeals for Agents, Software, and Machine Counterparties
**Submitted to:** Agentic AI Foundation (AAIF) / Linux Foundation
**Date:** March 2026
**Contact:** team@emiliaprotocol.ai
**License:** Apache-2.0
**Repository:** https://github.com/emiliaprotocol/emilia-protocol

---

## 1. Summary

EMILIA Protocol is an open protocol for making, explaining, challenging, and verifying trust decisions about agents, software, and machine counterparties.

Before an agent installs software, connects to a tool, accepts delegated authority, or transacts with a counterparty, EP returns a structured trust decision — with reasons and an appeal path.

MCP tells agents how to use tools. EP tells them whether they should.

This proposal asks AAIF to consider standardizing **EP Core** as a minimal interoperable trust-evaluation layer for agent systems. EP Core is deliberately small: **Trust Receipt**, **Trust Profile**, and **Trust Decision**. These three objects are sufficient to let independent implementations exchange trust-relevant evidence, summarize trust state, and make explainable, challengeable trust decisions without requiring any single vendor's private heuristics.

Disputes and appeals, delegation and attribution, zero-knowledge proofs, domain scoring, and install-preflight adapters are important EP extensions, but they should be advanced as optional extension tracks rather than prerequisites for Core adoption.

---

## 2. The Problem

Agent systems now have emerging standards for connectivity, communication, identity, and transaction flow. They still lack a portable way to answer a basic operational question:

**Should this agent, tool, package, plugin, server, or machine counterparty be trusted for this task in this context?**

Today that decision is usually made through private heuristics, internal allowlists, opaque marketplace controls, or host-specific memory. These approaches do not transfer across systems, are difficult to audit externally, and often provide little recourse when a trust-sensitive decision is wrong.

As agents begin installing software, routing work, acting under delegation, and transacting with counterparties, this gap becomes operational rather than theoretical. EP addresses that gap by standardizing a minimal interface for trust-relevant evidence, trust state, and trust decisions.

---

## 3. The Proposal

Standardize a minimal trust layer that any host, marketplace, agent framework, or operator can implement.

That minimal layer has three required objects:

### 3.1 Trust Receipt

A portable record of an observed event relevant to trust.

| Field | Description |
|-------|-------------|
| `subject` | The entity being described |
| `submitter` | The entity reporting the event |
| `event_type` | Category of observed behavior |
| `outcome` | What happened (completed, failed, disputed, etc.) |
| `timestamp` | When the event occurred |
| `provenance_tier` | Evidence quality classification (self-attested, bilateral, platform-observed, oracle-verified) |
| `transaction_ref` | Reference to the underlying transaction or interaction |
| `integrity_hash` | Cryptographic hash for tamper detection |
| `hash_chain_prev` | Link to the previous receipt in the chain |

A Trust Receipt is append-only. It records what happened. It does not interpret what it means.

### 3.2 Trust Profile

A standardized read object that summarizes the observable trust state of a subject entity.

| Field | Description |
|-------|-------------|
| `confidence_level` | How much the protocol trusts its own assessment (a function of evidence volume and quality) |
| `evidence_level` | Quantity and distribution of underlying receipts |
| `behavioral_rates` | Completion, retry, abandonment, and dispute rates |
| `provenance_summary` | Distribution of receipts across provenance tiers |
| `disputes_summary` | Count, status, and outcomes of disputes involving this entity |
| `anomaly_flags` | Detected irregularities (thin graph, clustered submissions, velocity spikes) |
| `version` | Profile schema version for forward compatibility |

A Trust Profile is a computed read surface. It does not make decisions. It provides the structured input from which decisions are made.

### 3.3 Trust Decision

A policy-evaluated result for a specific action in a specific context.

| Field | Description |
|-------|-------------|
| `decision` | `allow`, `review`, or `deny` |
| `reasons` | Structured explanation of what drove the decision |
| `confidence` | How confident the evaluation is, given available evidence |
| `policy_used` | Which policy was applied (e.g., strict, standard, permissive, custom) |
| `evidence_sufficiency` | Whether the underlying evidence was adequate to decide |
| `appeal_path` | If adverse, the mechanism available to challenge the decision |

A Trust Decision is the protocol's primary operational output. It is not a score. It is an operational result with reasons and recourse.

**If a third party can implement these three objects and interoperate with other implementations, EP has a real standard core.**

---

## 4. Constitutional Requirement

EP operates under one governing doctrine:

**Any adverse trust effect must be explainable, challengeable, reviewable, and reversible when wrong.**

Trust must never be more powerful than appeal.

This is not a feature. It is a constitutional constraint on the protocol itself. If EP can influence installation, routing, access, or conversion, then the entity affected by that influence must have a defined path to contest it and a defined process by which errors are corrected.

The due-process lifecycle is append-only: submitted, challenged, under review, resolved, reversed, superseded. Nothing is erased.

---

## 5. Why This Is Needed Now

The need is not abstract reputation. It is operational safety in systems where agents act with increasing autonomy.

**Install preflight.** An agent is asked to install an MCP server or npm package. Should it? Based on what? Today there is no portable trust signal to consult — only the platform's own allowlist or the user's intuition.

**Tool routing.** An agent must choose between multiple available tools or services for a task. On what basis? Without a shared trust layer, the routing decision is opaque, non-portable, and unaccountable.

**Counterparty evaluation.** An agent is about to transact with a merchant, service, or other agent. Is the counterparty trustworthy for this type of transaction, in this context, at this value? No standard exists to answer this question portably.

**Delegation assurance.** An agent acts under delegated authority from a human principal. How should the quality of that delegation — and the agent's track record under delegation — factor into downstream trust? Today it does not factor at all.

Each of these scenarios is already occurring. Each will become more frequent and more consequential as agent autonomy increases. The trust layer that supports them should be standardized before the space fragments into incompatible private implementations.

---

## 6. First Deployment Wedge

The first use case should be **software and MCP install preflight**.

This is the strongest initial wedge because it is:

- **Easy to understand.** "Before installing, check trust."
- **Immediately necessary.** Agents installing unvetted software is a live risk today.
- **High consequence.** A bad install can compromise a host, exfiltrate data, or corrupt a workflow.
- **Measurable.** Install outcomes (success, failure, rollback, incident) produce clean receipt data.
- **Low friction for adopters.** A preflight check is a read operation. It does not require restructuring host internals.

The standard question becomes: **Before an agent installs or invokes a server, package, plugin, or app, how should trust be evaluated?**

EP provides the structured answer: a Trust Decision with reasons, confidence, and an appeal path if the decision is adverse.

---

## 7. What Is in Scope for v1 Core

The v1 core standard defines only what is necessary for interoperable trust decisions:

- Trust Receipt schema and integrity requirements
- Trust Profile schema and computation requirements
- Trust Decision schema and policy evaluation interface
- Provenance tier definitions
- Basic dispute state fields (enough to populate the appeal path in a Trust Decision)
- Policy interface specification (built-in policies: strict, standard, permissive, discovery)
- Conformance test suite for all three core objects

---

## 8. What Is Explicitly Out of Scope for v1 Core

The following capabilities are valuable but should be standardized as optional extensions, not as entry requirements:

| Extension | Description |
|-----------|-------------|
| **Disputes and appeals** | Full dispute lifecycle, trust-graph adjudication, voucher-based resolution |
| **Delegation and attribution chain** | Principal-Agent-Tool attribution records, delegation judgment scoring |
| **Domain-specific scoring** | Vertical-specific behavioral weights and context keys |
| **Zero-knowledge proofs** | Privacy-preserving trust attestation for regulated industries |
| **Auto-receipt generation** | Passive behavioral data capture from MCP tool calls |
| **Software install preflight adapters** | Platform-specific adapters for GitHub Apps, npm packages, MCP servers |
| **EP Commit** | Signed pre-action authorization tokens proving policy evaluation before proceeding |

Product and operator surfaces — explorer, leaderboards, registry views, hosted dashboards, managed adjudication workflows — are implementation choices, not part of the standard at any layer.

---

## 9. Reference Implementation

EMILIA Protocol is offered as one strong working starting point for the standard — not as the standard itself.

The reference implementation includes:

- A deployed REST API implementing all three core objects
- An MCP server published on npm
- A conformance suite (JavaScript and Python)
- Example adapters for MCP server and software install preflight
- A dispute and appeal lifecycle implementation
- Privacy-preserving trust proofs (zero-knowledge commitment scheme)
- Attribution chain and delegation judgment scoring

The reference implementation deliberately includes capabilities beyond the v1 core scope. This is intentional: it demonstrates that the core is extensible without requiring extensions for basic interoperability.

The reference implementation is not the standard. It is the starting point from which the working group extracts, refines, and ratifies the standard.

---

## 10. Integration with AAIF Projects

EP is a composable layer. It does not compete with existing AAIF projects. It attaches to them.

| AAIF Project | Integration Point |
|-------------|-------------------|
| **MCP** | Trust decisions before tool invocation; trust receipts from tool outcomes |
| **A2A** | Trust context in Agent Cards for routing decisions |
| **ACP** | Trust evaluation before payment flows; merchant trust profiles |

Tool access is not trust. Commerce flow is not trust. Identity is not trust. Communication is not trust. Trust is the question that remains after connectivity, identity, and transaction mechanics are solved.

---

## 11. Governance Principle

The trust layer must not be owned by any single marketplace, model vendor, or platform operator.

**Trust evaluation creates both operational and governance concerns when the same platform both participates in and adjudicates trust-sensitive transactions. A neutral standard reduces real and perceived conflicts of interest by allowing trust decisions to be made through portable, inspectable, challengeable interfaces rather than platform-specific heuristics.**

Under neutral governance:

- No single company can manipulate trust to favor its own products
- The evaluation logic remains open source and auditable
- Multiple independent implementations can emerge and interoperate
- Conformance testing ensures that "EP-compatible" means something verifiable

---

## 12. Why EP Is a Strong Starting Point

EP already demonstrates, in working code:

- A trust profile model with behavioral rates, confidence levels, and anomaly detection
- Policy evaluation returning structured decisions with reasons
- A dispute and appeal lifecycle with due-process guarantees
- Software install preflight for MCP servers, GitHub Apps, and npm packages
- Portability across REST API and MCP surfaces
- Cross-language conformance verification
- An open-source implementation under Apache 2.0

EP is not the only possible starting point. It is one that already works, is already open, and is already structured around the three-object core this proposal defines.

---

## 13. The Ask

We propose that AAIF form or support a neutral working group to define the minimal trust evaluation layer for agent systems.

**Starting from:** a live open reference implementation.
**Scoped to:** a small interoperable core (receipt, profile, decision).
**Governed by:** the principle that trust must never be more powerful than appeal.

### Proposed structure

- **Chair:** EMILIA Protocol (initial), rotating annually
- **Membership:** Open to any AAIF member organization
- **Core deliverable:** EP Core Spec v1.0 — Trust Receipt, Trust Profile, Trust Decision schemas and conformance tests
- **Extension deliverables:** Dispute lifecycle, attribution chain, privacy-preserving proofs — scoped and sequenced by the working group
- **Timeline:** Core spec draft Q2 2026, ratification Q3 2026, conformance suite Q4 2026
- **Meetings:** Biweekly, open to all AAIF members

---

## Appendix A: Current Implementation Maturity

The following reflects the state of the EP reference implementation as of March 2026. This is provided for context on what exists as a starting point, not as a definition of what the standard must include.

### Core protocol

| Component | Status |
|-----------|--------|
| Trust Receipt schema with provenance tiers and integrity hashing | Deployed |
| Trust Profile endpoint (`GET /api/trust/profile/:entityId`) | Deployed |
| Policy evaluation (`POST /api/trust/evaluate`) with 4 built-in policies | Deployed |
| Context-aware evaluation (receipt filtering by task type, category, geo, modality, value band, risk class) | Deployed |
| Canonical receipt pipeline with unified ingestion path | Deployed |
| Behavioral-first scoring (behavioral 40%, consistency 25%, weights sum to 1.00) | Deployed |
| Current vs. historical confidence separation | Deployed |
| Canonical JSON hashing (sorted keys, deterministic, cross-language) | Deployed |

### Integrity and resistance

| Component | Status |
|-----------|--------|
| Receipt immutability (database triggers reject content changes) | Deployed |
| Effective-evidence Sybil resistance (dampening toward 50 based on weighted evidence) | Deployed |
| Graph weight penalties (closed-loop 0.4x, cluster 0.1x + blocked) | Deployed |
| Identity-aware write throttling (API key prefix + IP on writes, IP-only on reads) | Deployed |
| Portable owner identity (`ep_owner_<uuid>`) with principal binding via `/api/identity/bind` | Deployed |

### Extensions (implemented, proposed as optional standard extensions)

| Component | Status |
|-----------|--------|
| Zero-knowledge trust proofs (HMAC-SHA256 commitment scheme) | Deployed |
| Attribution chain (Principal-Agent-Tool with verified accountability) | Deployed |
| Delegation judgment scoring | Deployed |
| Auto-receipt generation from MCP tool calls (opt-in, privacy-by-default) | Deployed |
| Trust-graph dispute adjudication (voucher network resolution) | Deployed |

### Tooling and testing

| Component | Status |
|-----------|--------|
| MCP server (29 tools, context-aware) | Published on npm |
| Conformance suite (28 test files, 670+ automated checks, CI-backed) | Complete |
| Cross-language verification (JavaScript + Python) | Complete |
| Install preflight for MCP servers, GitHub Apps, npm packages | Deployed |

### External integrations

| Component | Status |
|-----------|--------|
| Shopify DTC integration spec (webhook mapping, receipt mapping, MVP roadmap) | Complete |
| NIST ITL Concept Paper | Prepared |

---

*EMILIA Protocol — Portable trust evaluation and appeals for agents, software, and machine counterparties.*
*Decisions, not scores. Reasons, not thresholds. Due process, not silent gatekeeping.*
*Compatible with ACP. Usable through MCP. Open source under Apache 2.0.*
