# EMILIA Protocol

[![CI](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## What is EP?

**EMILIA Protocol (EP) is a protocol-grade trust substrate for high-risk action enforcement.**

**EP does not stop at identity. It verifies whether a specific actor, operating under a specific authority context, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and durable event traceability.**

**EP enforces trust before high-risk action.**

EP is not a generic identity platform, not a wallet, and not a social reputation layer. It is protocol infrastructure for binding actor identity, authority, policy, and exact action context before execution.

**EP Core** consists of three interoperable objects:
- Trust Receipt
- Trust Profile
- Trust Decision

**EP Extensions** add stronger enforcement for high-risk workflows. The most important extension is **Handshake**, which binds actor identity, authority, policy, exact action context, nonce, expiry, and one-time consumption into a pre-action authorization flow.

When policy requires named human ownership, EP can also require **Accountable Signoff** before execution.

The protocol is open. Managed policy, verification, signoff orchestration, monitoring, evidence tooling, and sector-specific packs are optional product layers built on top.

---

## The EP stack

- **Emilia Eye** — lightweight warning layer that flags when stricter EP trust controls should apply
- **EP Handshake** — policy-bound pre-action trust enforcement
- **Accountable Signoff** — named human ownership when policy requires it

> **Eye warns. EP verifies. Signoff owns.**

---

## Proof points

| Metric | Value |
|---|---|
| Automated tests | 3,277 across 125 files |
| TLA+ safety properties | 20 — **Verified (TLC 2.19, 2026-04-02)** — see [formal/PROOF_STATUS.md](formal/PROOF_STATUS.md) |
| Alloy relational assertions | 32 facts, 15 assertions — **Verified (Alloy 6.1.0, 2026-04-02)** |
| Red team cases | 116 documented |
| Security findings remediated | 31 |
| CI quality gates | 27 across 12 automated workflows |
| Full 7-step signoff chain | Proven end-to-end under load |
| Handshake create p95 | 87ms at 500 VUs |

See [Performance Proof](docs/operations/PERFORMANCE_PROOF.md) | [Operating Envelope](docs/operations/OPERATING_ENVELOPE.md) | [Security Policy](SECURITY.md) | [Audit Methodology](docs/security/AUDIT_METHODOLOGY.md) | [API Compatibility Policy](docs/api/COMPATIBILITY.md)

## Conformance status

| Metric | Value |
|---|---|
| Spec version | v1.0 |
| Route parity (API ↔ OpenAPI) | see CI |
| Tests | see CI |
| Formal models | TLA+ + Alloy |
| CodeQL | Active |
| SBOM / Provenance | Active |

---

## EP Core / EP Extensions / EP Product Surfaces

EP is a three-layer system. The core is deliberately small. Everything else is either an optional extension or a product surface built on top.

- **EP Core** — the interoperable standard: **Trust Receipt**, **Trust Profile**, and **Trust Decision**.
- **EP Extensions** — stronger enforcement where systems must constrain execution:
  - Handshake
  - Accountable Signoff
  - Commit
  - Delegation and attribution
  - Disputes and appeals where governance requires them
- **EP Product Surfaces** — reference implementations and commercial layers:
  - Open runtime
  - Cloud control plane
  - Enterprise deployment layer
  - Government, financial, and agent-governance packs

A skeptical reader should be able to answer in 30 seconds:
Core = the minimum interoperable standard.
Extensions = stronger enforcement you opt into.
Product Surfaces = tools built on top, not the protocol itself.

---

## Four canonical high-risk action contexts

EP is decision infrastructure. Every serious deployment should anchor to a concrete action surface such as:

| Context | Example |
|---|---|
| Government | payment destination change, benefit redirect, operator override |
| Financial | beneficiary change, payout destination change, treasury approval |
| Enterprise | privileged production change, secrets rotation, permission escalation |
| AI / Agent | destructive tool use, autonomous irreversible action |

---

## Three core objects

EP standardizes three interoperable objects:

| Object | What it is | One-line |
|---|---|---|
| Trust Receipt | A portable record of an observed event relevant to trust | What happened |
| Trust Profile | A standardized summary of observable trust state | What is known |
| Trust Decision | A policy-evaluated result with reasons and appeal path | What to do now |

If a third party can implement these three objects and interoperate, EP has a real standard.

---

## Quickstart in five calls

1. create policy
2. initiate handshake
3. present evidence
4. verify
5. signoff and consume

That is the irreducible EP story.

---

## Why EP exists

Most systems verify who is acting.
Very few verify whether **this exact high-risk action** should be allowed to proceed **under this exact policy** by **this exact actor** right now.

That is the gap EP closes.
