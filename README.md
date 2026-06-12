# EMILIA Protocol

[![CI](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-join%20the%20community-5865F2?logo=discord&logoColor=white)](https://discord.gg/MSJXjEtD4)

**A named human's signed "yes" before an AI agent does anything irreversible — with a receipt anyone can verify offline.**

Three independent reference verifiers — **JavaScript, Python, and Go** — are proven to agree on the canonical adversarial conformance vectors, on every push (`npm run conformance`). That is the IETF bar for a real standard: multiple independent interoperable implementations. See [CONFORMANCE.md](CONFORMANCE.md), or verify a receipt yourself, in your browser, at [emiliaprotocol.ai/verify](https://www.emiliaprotocol.ai/verify).

![EMILIA crash test — an autonomous agent tries to wire $82,000; the formally-verified policy engine holds it, a named human signs off, the Trust Receipt verifies offline, and a forged copy fails verification.](docs/media/crash-test.gif)

> Run it yourself: `node examples/crash-test.mjs` — fully offline, no API key.

Try it in one line (Claude / Cursor / Cline):

```bash
npx -y @emilia-protocol/mcp-server
```

**[90-second demo](https://www.emiliaprotocol.ai/mcp)** · **[Quickstart](https://www.emiliaprotocol.ai/quickstart)** · **[Agent code walkthrough](https://www.emiliaprotocol.ai/use-cases/ai-agent)** · **[Discord](https://discord.gg/MSJXjEtD4)**

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

- **EP Eye** — observes and classifies agent behavior (OBSERVE → SHADOW → ENFORCE)
- **EP Handshake** — cryptographic consent ceremony with 7-property binding
- **EP Signoff** — named human ownership of outcomes
- **EP Commit** — atomic, immutable action close

> **Eye observes. Handshake verifies. Signoff owns. Commit seals.**

---

## Proof points

| Metric | Value |
|---|---|
| Automated tests | 3,500 across 134 files (npx vitest run, 2026-06-09) |
| TLA+ safety properties | 26 verified (T1-T26) - TLC 2.19, latest full run 2026-04-30, 0 errors - see [formal/PROOF_STATUS.md](formal/PROOF_STATUS.md) |
| Alloy relational assertions | 35 facts, 15 assertions - verified in CI (Alloy 6.0.0, 2026-04-30) |
| Red team cases | 85 cataloged in [docs/conformance/RED_TEAM_CASES.md](docs/conformance/RED_TEAM_CASES.md) |
| Security findings remediated | 31 |
| CI quality gates | See `.github/workflows/` (~13 workflows) |
| Full 7-step signoff chain | Proven end-to-end under load |
| Handshake create p95 | 575ms at 50 VUs (per [docs/operations/PERFORMANCE_PROOF.md](docs/operations/PERFORMANCE_PROOF.md)) |

See [Performance Proof](docs/operations/PERFORMANCE_PROOF.md) | [Operating Envelope](docs/operations/OPERATING_ENVELOPE.md) | [Security Policy](SECURITY.md) | [Audit Methodology](docs/security/AUDIT_METHODOLOGY.md) | [API Compatibility Policy](docs/api/COMPATIBILITY.md)

## Conformance status

| Metric | Value |
|---|---|
| Spec version | EP-CORE-v1.0 |
| Conformance test | **7/7 required checks pass against production** (verified 2026-06-12) — run it yourself: `node conformance/ep-conformance-test.js https://www.emiliaprotocol.ai` (discovery · key publication · entity registration · EP-RECEIPT-v1 format · Ed25519 signature · trust profile · trust decision) |
| Standalone verify | `npm install @emilia-protocol/verify` — zero deps, Apache-2.0 ([npmjs.com](https://www.npmjs.com/package/@emilia-protocol/verify)) |
| Embed widget | `<ep-trust-badge entity-id="...">` |
| Discovery | `/.well-known/ep-trust.json` + `/.well-known/ep-keys.json` |
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
