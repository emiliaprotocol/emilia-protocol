# EP Core Manifest

**Version:** 1.0
**Status:** Normative
**Last updated:** 2026-03-20

This document defines the hard boundary between the Emilia Protocol kernel and everything built on top of it. The protocol kernel is small and severe. Everything outside it is product.

---

## 1. Protocol Kernel

The trust core. These modules implement the protocol specification. They are the only code that may perform trust-bearing state transitions. Every write flows through `protocolWrite()`. Every read of trust state flows through the canonical evaluator. No exceptions.

### 1.1 Handshake Engine

The central protocol primitive. A handshake is a structured, cryptographically-bound trust ceremony between parties.

| File / Directory | Role |
|---|---|
| `lib/handshake/index.js` | Barrel re-export; public API surface |
| `lib/handshake/create.js` | `initiateHandshake` — create a pending handshake with binding material |
| `lib/handshake/present.js` | `addPresentation` — party submits identity proof / credentials |
| `lib/handshake/verify.js` | `verifyHandshake` — evaluate all presentations against policy, produce outcome |
| `lib/handshake/consume.js` | `consumeHandshake` — one-time consumption of a verified handshake |
| `lib/handshake/finalize.js` | `revokeHandshake` — cancel or revoke a handshake |
| `lib/handshake/policy.js` | Policy resolution, validation, claim checking |
| `lib/handshake/binding.js` | Canonical binding material computation and hashing (SINGLE source of truth) |
| `lib/handshake/invariants.js` | Pure invariant checks, constants, crypto helpers (no side effects, no DB) |
| `lib/handshake/normalize.js` | Claims normalization and canonical hashing |
| `lib/handshake/schema.js` | Handshake input validation schemas |
| `lib/handshake/events.js` | Append-only handshake event sourcing (immutable audit trail) |
| `lib/handshake/errors.js` | `HandshakeError` class |
| `lib/handshake/bind.js` | Binding and delegation integrity checks |
| `lib/handshake/storage.js` | Handshake persistence primitives |

### 1.2 Canonical Write Path

All trust-changing state transitions funnel through a single choke point. No route handler may write to trust tables directly.

| File | Role |
|---|---|
| `lib/protocol-write.js` | `protocolWrite()` — the single entry point for all trust-bearing writes. Enforces: validation, evaluation, authorization, idempotency, event persistence, projection materialization |
| `lib/canonical-writer.js` | Implementation layer for receipt/dispute writes (called by `protocolWrite`, never directly by routes) |
| `lib/write-guard.js` | Runtime enforcement proxy that blocks direct mutations on trust tables from route handlers |

### 1.3 Commit System

Signed pre-action authorization tokens proving that a machine action was evaluated under policy BEFORE the action proceeded.

| File | Role |
|---|---|
| `lib/commit.js` | `issueCommit`, `verifyCommit`, `revokeCommit` — Ed25519-signed authorization lifecycle |
| `lib/commit-auth.js` | Commit authentication and key management |

### 1.4 Trust Evaluation

The canonical read path. One function that every trust-consuming surface calls.

| File | Role |
|---|---|
| `lib/canonical-evaluator.js` | `canonicalEvaluate` — single function for all trust reads. Inputs: entity, context, policy. Outputs: profile, confidence, anomaly, policy result |
| `lib/trust-decision.js` | `buildTrustDecision` — canonical output shape for every decision surface |
| `lib/scoring-v2.js` | Trust score computation, policy evaluation, weight model |
| `lib/scoring.js` | Legacy scoring (v1, retained for migration) |

### 1.5 Policy

Rules that govern trust ceremonies.

| File | Role |
|---|---|
| `lib/handshake/policy.js` | Handshake policy schema, validation, resolution, claim checking |
| `app/api/policies/route.js` | Policy listing endpoint |

### 1.6 Delegation

Signed authorization chains: a principal grants an agent the right to act on their behalf within defined scope.

| File | Role |
|---|---|
| `lib/delegation.js` | `createDelegation`, `verifyDelegation`, `revokeDelegation` |

### 1.7 Cryptographic Primitives

| File | Role |
|---|---|
| `lib/signatures.js` | Ed25519 receipt signature verification |
| `lib/handshake/invariants.js` | SHA-256 hashing, nonce generation |

### 1.8 Protocol Identity

| File | Role |
|---|---|
| `lib/protocol-version.js` | `EP_PROTOCOL_VERSION` — spec version, scoring model, hash algorithm |
| `lib/errors.js` | `ProtocolWriteError`, `TrustEvaluationError`, RFC 7807 error envelope |

### 1.9 Conformance

| File / Directory | Role |
|---|---|
| `conformance/` | Conformance test suite |
| `CONFORMANCE.md` | Conformance specification |

### 1.10 Protocol API Routes (Kernel Surface)

These routes expose the kernel operations over HTTP. They are thin wrappers that validate input and delegate to kernel functions.

| Route | Operation |
|---|---|
| `app/api/handshake/route.js` | POST: initiate handshake; GET: list handshakes |
| `app/api/handshake/[handshakeId]/route.js` | GET: retrieve handshake state |
| `app/api/handshake/[handshakeId]/present/route.js` | POST: add presentation |
| `app/api/handshake/[handshakeId]/verify/route.js` | POST: verify handshake |
| `app/api/handshake/[handshakeId]/revoke/route.js` | POST: revoke handshake |
| `app/api/commit/issue/route.js` | POST: issue commit |
| `app/api/commit/verify/route.js` | POST: verify commit |
| `app/api/commit/[commitId]/route.js` | GET: retrieve commit |
| `app/api/commit/[commitId]/revoke/route.js` | POST: revoke commit |
| `app/api/commit/keys/route.js` | GET: public signing keys |
| `app/api/delegations/create/route.js` | POST: create delegation |
| `app/api/delegations/[delegationId]/verify/route.js` | POST: verify delegation |
| `app/api/policies/route.js` | GET: list policies |
| `app/api/trust/evaluate/route.js` | POST: canonical trust evaluation |
| `app/api/trust/gate/route.js` | POST: trust gate (pass/fail decision) |
| `app/api/verify/[receiptId]/route.js` | GET: verify receipt |
| `app/api/receipts/submit/route.js` | POST: submit receipt |
| `app/api/receipts/confirm/route.js` | POST: bilateral confirmation |
| `app/api/disputes/file/route.js` | POST: file dispute |
| `app/api/disputes/resolve/route.js` | POST: resolve dispute |
| `app/api/disputes/respond/route.js` | POST: respond to dispute |
| `app/api/disputes/appeal/route.js` | POST: appeal dispute |
| `app/api/disputes/withdraw/route.js` | POST: withdraw dispute |
| `app/api/disputes/report/route.js` | POST: file human report |
| `app/api/health/route.js` | GET: health check |

---

## 2. Operator Surface

Infrastructure and operational concerns. Necessary for running an EP node, but not part of the protocol specification. An EP implementation could replace these entirely with different operational tooling.

| File / Route | Role |
|---|---|
| `lib/supabase.js` | Database client factory (Supabase-specific; swappable) |
| `lib/env.js` | Environment configuration loading |
| `lib/rate-limit.js` | Rate limiting (operational, not protocol) |
| `middleware.js` | HTTP middleware: auth, CORS, rate limiting |
| `app/api/cron/expire/route.js` | Cron: expire stale commits/handshakes |
| `app/api/audit/route.js` | Audit log retrieval |
| `app/api/stats/route.js` | System statistics |
| `app/api/health/route.js` | Health check (also listed under kernel for liveness) |
| `app/api/operators/apply/route.js` | Operator application |
| `supabase/` | Database migrations and configuration |
| `lib/blockchain.js` | Blockchain anchoring adapter (optional integrity proof) |
| `app/api/blockchain/anchor/route.js` | Blockchain anchor endpoint |
| `lib/adapters/` | Storage/provider adapters |
| `lib/providers/` | External service providers |
| `scripts/` | Deployment and maintenance scripts |
| `Dockerfile` | Container build |
| `docker-compose.yml` | Local development environment |
| `vercel.json` | Deployment configuration |

---

## 3. Product Surface

Business features built ON the protocol. These consume trust decisions but do not produce them. Removing any of these would not break the protocol. They exist to demonstrate EP's value, not to define it.

### 3.1 Product API Routes

| Route | Category |
|---|---|
| `app/api/entities/register/route.js` | Entity management |
| `app/api/entities/search/route.js` | Entity discovery |
| `app/api/entities/[entityId]/auto-receipt/route.js` | Automated receipt submission |
| `app/api/needs/[id]/claim/route.js` | Marketplace: claim a need |
| `app/api/needs/[id]/complete/route.js` | Marketplace: complete a need |
| `app/api/needs/[id]/rate/route.js` | Marketplace: rate completion |
| `app/api/needs/broadcast/route.js` | Marketplace: broadcast needs |
| `app/api/feed/route.js` | Activity feed |
| `app/api/leaderboard/route.js` | Trust leaderboard |
| `app/api/score/[entityId]/route.js` | Score retrieval (product wrapper around canonical evaluator) |
| `app/api/score/[entityId]/history/route.js` | Score history |
| `app/api/trust/profile/[entityId]/route.js` | Trust profile page data |
| `app/api/trust/install-preflight/route.js` | Software pre-action enforcement (experimental) |
| `app/api/trust/domain-score/[entityId]/route.js` | Domain-specific scoring |
| `app/api/trust/zk-proof/route.js` | ZK proof generation |
| `app/api/inquiries/route.js` | Contact form |
| `app/api/waitlist/route.js` | Waitlist signup |
| `app/api/identity/bind/route.js` | Identity binding UI flow |
| `app/api/identity/verify/route.js` | Identity verification UI flow |
| `app/api/identity/continuity/` | Identity continuity (EP-IX extension) |
| `app/api/identity/lineage/` | Identity lineage tracking |
| `app/api/identity/principal/` | Principal-agent relationship management |
| `app/api/receipts/auto-submit/route.js` | Auto-receipt configuration |
| `app/api/commit/[commitId]/receipt/route.js` | Commit-to-receipt linking |
| `app/api/commit/[commitId]/dispute/route.js` | Commit dispute UI flow |
| `app/api/disputes/[disputeId]/route.js` | Dispute detail retrieval |
| `app/api/disputes/[disputeId]/adjudicate/route.js` | Adjudication workflow |
| `app/api/disputes/appeal/resolve/route.js` | Appeal resolution workflow |

### 3.2 Product Libraries

| File | Category |
|---|---|
| `lib/auto-receipt-config.js` | Auto-receipt business logic |
| `lib/attribution.js` | Attribution tracking |
| `lib/domain-scoring.js` | Domain-specific score computation |
| `lib/ep-ix.js` | EP-IX identity continuity extension |
| `lib/procedural-justice.js` | Dispute adjudication workflow logic |
| `lib/dispute-adjudication.js` | Dispute adjudication engine |
| `lib/sybil.js` | Sybil resistance heuristics |
| `lib/zk-proofs.js` | Zero-knowledge proof generation |
| `lib/create-receipt.js` | Receipt creation helpers |
| `lib/handshake-auth.js` | Handshake authentication middleware (product-level auth, not protocol auth) |

### 3.3 Product UI

| Directory | Category |
|---|---|
| `app/appeal/` | Appeal submission page |
| `app/apply/` | Operator application page |
| `app/entity/` | Entity profile page |
| `app/governance/` | Governance dashboard |
| `app/investors/` | Investor information page |
| `app/operators/` | Operator dashboard |
| `app/partners/` | Partner information page |
| `app/quickstart/` | Quick start guide |
| `app/score/` | Score lookup page |
| `app/spec/` | Specification viewer |
| `components/` | React UI components |
| `content/` | Static content and copy |
| `public/` | Static assets |

### 3.4 Extensions and SDKs

| Directory | Category |
|---|---|
| `sdks/typescript/` | TypeScript SDK |
| `sdks/python/` | Python SDK |
| `cli/` | CLI tool |
| `mcp-server/` | MCP server integration |
| `formal/` | Formal verification artifacts |

---

## 4. The Rule

```
Protocol Kernel:  25 files.  ~3,200 lines of trust logic.
Operator Surface: ~15 files. Replaceable without protocol change.
Product Surface:  ~60 files. Removable without protocol change.
```

If you are modifying a file in Section 1, you are changing the protocol. This requires:
- Conformance test coverage
- Protocol version consideration
- Security review

If you are modifying a file in Section 2 or 3, you are changing operations or product. The protocol is unaffected.

The kernel's only job is to answer one question: **"Should this action be trusted, and can I prove that the question was asked?"**

Everything else is surface.
