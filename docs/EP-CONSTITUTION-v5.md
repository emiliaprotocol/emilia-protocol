# EMILIA Protocol Constitution v5

**Supersedes:** ep_constitution_v4_architecture.docx  
**Date:** April 2026  
**Status:** Active  

---

## Preamble

This constitution defines the foundational principles, governance structure, and architectural invariants of the EMILIA Protocol. It is the highest-authority document in the EP canon. No PIP, no implementation, and no commercial decision may violate these principles.

---

## Article I — Mission

EMILIA Protocol exists to ensure that every consequential action taken by or on behalf of AI systems has a verifiable, tamper-evident, policy-bound authorization record — attributable to a specific actor, under a specific policy, at a specific time.

**One sentence:** EP is the proof that an AI asked permission before it acted.

---

## Article II — Core Principles

### 1. Trust before action
No high-risk action proceeds without verified authorization. This is not advisory — it is enforcement.

### 2. Verifiable by anyone
EP receipts are self-contained, Ed25519-signed, and Merkle-anchored. Anyone can verify them without EP infrastructure, without an account, without any trust relationship with the operator. Like Bitcoin transactions — just math.

### 3. Named human accountability
When an AI acts with real-world consequences, a specific named human — not a role, not a team, a person — must have seen the exact action, understood the consequences, and accepted responsibility.

### 4. Due process above trust
Trust must never be more powerful than appeal. Every trust decision is contestable. Every entity has access to dispute, appeal, and human review. EP will never build a trust system where a low score is a permanent sentence.

### 5. Open protocol, not a product
EP is Apache 2.0. The protocol is free. The specification is public. The formal verification models are open. Commercial offerings (EP Cloud) sustain development but never gate protocol functionality.

### 6. Federated, not centralized
EP is designed for multiple independent operators. No single operator, no single database, no single jurisdiction controls the protocol. Operators cross-verify via cryptographic proofs.

### 7. Immutable core, extensible edges
EP Core v1.0 (Trust Receipt, Trust Profile, Trust Decision) is frozen. Changes require a PIP, 90-day review, consensus, major version bump, and 24-month deprecation. Extensions are added freely.

---

## Article III — Protocol Architecture

### The Four Layers

```
EP Eye         OBSERVE → SHADOW → ENFORCE
               Classifies risk. Informs policy. Does not decide.

EP Handshake   Pre-action trust ceremony
               7 properties: identity, authority, policy, action, nonce, expiry, consumption

EP Signoff     Named human accountability
               Specific principal. Irrevocable. One-time consumable.

EP Commit      Atomic action seal
               Immutable. Hash-linked. Blockchain-anchored. No partial states.
```

### The Three Core Objects (Frozen)

| Object | Purpose |
|--------|---------|
| **Trust Receipt** | Self-contained, signed, portable record of a trust-relevant interaction |
| **Trust Profile** | Structured trust state derived from receipts (score, confidence, evidence, domains) |
| **Trust Decision** | Policy-evaluated result: allow/review/deny with reasons and appeal path |

### Architectural Invariants

1. A handshake can only be consumed once
2. An entity can only generate commitment proofs for itself
3. Trust table writes are service_role only (write guard enforced)
4. Blockchain anchoring must not silently skip in production
5. Commitment proofs never reveal the receipt set
6. Tenant isolation is fail-closed
7. Every trust-changing state transition is logged before execution
8. Signed receipts are verifiable without EP infrastructure
9. Policy is hash-locked at handshake initiation — drift between initiation and verification is rejected

---

## Article IV — Governance

### Protocol Improvement Proposals (PIPs)

All protocol changes go through the PIP process (PIP-000):

- **Core PIPs:** 90-day review, consensus, major version bump, 24-month deprecation
- **Extension PIPs:** Standard review, no core breakage
- **Interface PIPs:** API surface changes
- **Process PIPs:** Governance changes

### Current PIPs

| PIP | Title | Status |
|-----|-------|--------|
| PIP-000 | PIP Process | Active |
| PIP-001 | EP Core v1.0 Freeze | Accepted |
| PIP-002 | Handshake Extension | Accepted |
| PIP-003 | Accountable Signoff | Accepted |
| PIP-004 | EP Commit | Accepted |
| PIP-005 | Emilia Eye | Accepted |
| PIP-006 | Federation | Draft |

### Decision Authority

| Decision | Authority |
|----------|-----------|
| Core protocol changes | PIP process + consensus |
| Extension additions | PIP process |
| Commercial strategy | CEO |
| Security response | Protocol Author + CEO |
| License changes | Never (Apache 2.0 is irrevocable) |

---

## Article V — Compliance Posture

EP maintains formal compliance mappings for:

| Framework | Status |
|-----------|--------|
| NIST AI RMF 1.0 | 38/38 subcategories mapped |
| EU AI Act | Articles 9-15 and 26 fully mapped |
| SOC 2 Type II | Audit engagement planned |

These mappings cite specific EP primitives — not aspirational capabilities.

---

## Article VI — Federation

EP is designed for a federated world where multiple operators run independent EP instances:

1. **Operators don't trust each other** — they verify via cryptographic proofs
2. **Receipts are portable** — Ed25519-signed, Merkle-anchored, verifiable offline
3. **Trust profiles are local** — each operator computes from receipts they've seen
4. **Anchor layer is shared** — Base L2 Merkle roots provide tamper evidence
5. **Discovery is decentralized** — `/.well-known/ep-trust.json` and `/.well-known/ep-keys.json`

---

## Article VII — What EP Will Never Do

1. **Never require a token** to use the protocol. No cryptocurrency. No DeFi. No trading.
2. **Never gate protocol functionality** behind commercial offerings. EP Cloud is a convenience layer, not a feature gate.
3. **Never produce permanent reputation labels.** Trust decisions are contextual, not persistent sentences.
4. **Never allow trust to override appeal.** Due process is architecturally guaranteed.
5. **Never centralize control.** Federation is the design target. Single-operator mode is a starting point, not the end state.
6. **Never silently fail.** All trust-bearing operations fail closed. Unlogged state transitions are never acceptable.

---

## Article VIII — Amendments

This constitution may be amended by:
1. A Process-type PIP
2. 90-day public review
3. Consensus among active maintainers
4. Version bump to this document

Article VII (What EP Will Never Do) is unamendable.

---

*Ratified April 2026. This document supersedes ep_constitution_v4_architecture.docx.*
