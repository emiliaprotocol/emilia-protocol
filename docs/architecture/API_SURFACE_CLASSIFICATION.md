# EP API Surface Classification

> **Purpose**: Classify every endpoint in the EMILIA Protocol API to distinguish
> the protocol-essential trust substrate from product and operator surfaces.
> This document addresses the lightweightness concern: the OpenAPI spec exposes
> many tags and endpoints, but only a small core participates in trust enforcement.

## Summary

**EP Protocol Core exposes 17 endpoints.** The remaining 42 endpoints are product,
operator, or system surfaces that do not participate in trust enforcement.

| Classification | Count | Percentage |
|---|---|---|
| Protocol-Essential | 17 | 29% |
| Trust-Adjacent | 11 | 19% |
| Operator-Essential | 5 | 8% |
| Product Surface | 16 | 27% |
| Non-Core / Legacy | 10 | 17% |
| **Total** | **59** | |

**Protocol-essential ratio: 17 / 59 = 29%.** For a protocol spec, only the 17
protocol-essential endpoints should appear. Integrators need to read and
implement against fewer than 20 endpoints.

---

## Classification: Protocol-Essential

These endpoints form the trust substrate. They implement handshake, commit,
trust evaluation, policy, and delegation -- the primitives required to make
and enforce trust decisions.

| # | Endpoint | Method | Tag | Role |
|---|----------|--------|-----|------|
| 1 | `/api/trust/evaluate` | POST | Trust | Evaluate entity against a trust policy; returns allow/review/deny |
| 2 | `/api/trust/gate` | POST | Trust | Pre-action trust gate; issues commit on allow |
| 3 | `/api/trust/profile/{entityId}` | GET | Trust | Canonical read surface for trust data |
| 4 | `/api/handshake` | POST | Handshake | Initiate a structured identity exchange |
| 5 | `/api/handshake` | GET | Handshake | List handshakes for the authenticated entity |
| 6 | `/api/handshake/{handshakeId}` | GET | Handshake | Get full handshake state |
| 7 | `/api/handshake/{handshakeId}/present` | POST | Handshake | Add identity presentation to handshake |
| 8 | `/api/handshake/{handshakeId}/verify` | POST | Handshake | Evaluate presentations against policy |
| 9 | `/api/handshake/{handshakeId}/revoke` | POST | Handshake | Revoke an active handshake |
| 10 | `/api/commit/issue` | POST | Commits | Issue a signed pre-action authorization token |
| 11 | `/api/commit/verify` | POST | Commits | Verify a commit's authenticity and status |
| 12 | `/api/commit/{commitId}` | GET | Commits | Get commit details |
| 13 | `/api/commit/{commitId}/revoke` | POST | Commits | Revoke an issued commit |
| 14 | `/api/commit/{commitId}/receipt` | POST | Commits | Attach receipt to a commit |
| 15 | `/api/commit/{commitId}/dispute` | POST | Commits | Dispute a commit |
| 16 | `/api/policies` | GET | Policies | List available trust policies |
| 17 | `/api/delegations/create` | POST | Delegations | Create a principal-agent delegation |

---

## Classification: Trust-Adjacent

These endpoints support the trust lifecycle but are not strictly required for
the core handshake/commit/evaluate loop. They provide evidence, verification,
dispute resolution, and identity primitives that the protocol depends on.

| # | Endpoint | Method | Tag | Role |
|---|----------|--------|-----|------|
| 1 | `/api/delegations/{delegationId}/verify` | POST | Delegations | Verify a delegation's validity |
| 2 | `/api/receipts/submit` | POST | Receipts | Submit a transaction receipt (trust evidence) |
| 3 | `/api/receipts/confirm` | POST | Receipts | Bilateral receipt confirmation |
| 4 | `/api/verify/{receiptId}` | GET | Receipts | Verify receipt hash integrity |
| 5 | `/api/disputes/file` | POST | Disputes | File a dispute against an entity |
| 6 | `/api/disputes/respond` | POST | Disputes | Respond to a dispute |
| 7 | `/api/disputes/resolve` | POST | Disputes | Resolve a dispute |
| 8 | `/api/disputes/appeal` | POST | Disputes | Appeal a dispute resolution |
| 9 | `/api/disputes/appeal/resolve` | POST | Disputes | Resolve an appeal |
| 10 | `/api/disputes/withdraw` | POST | Disputes | Withdraw a filed dispute |
| 11 | `/api/disputes/{disputeId}` | GET | Disputes | Get dispute details |

---

## Classification: Operator-Essential

Endpoints required by operators to run and monitor an EP node, but not part
of the protocol specification itself.

| # | Endpoint | Method | Tag | Role |
|---|----------|--------|-----|------|
| 1 | `/api/health` | GET | System | Health check |
| 2 | `/api/audit` | GET | System | Query the append-only audit trail |
| 3 | `/api/cron/expire` | GET | Internal | Expire stale records (cron job) |
| 4 | `/api/blockchain/anchor` | POST | Internal | Anchor receipts to blockchain (cron) |
| 5 | `/api/blockchain/anchor` | GET | Internal | Anchor alias for Vercel Cron |

---

## Classification: Product Surface

Endpoints that serve the emiliaprotocol.ai product experience -- entity
management, marketplace, search, content, and marketing. These exist to make
the product useful but are not part of the trust protocol.

| # | Endpoint | Method | Tag | Role |
|---|----------|--------|-----|------|
| 1 | `/api/entities/register` | POST | Entities | Register a new entity |
| 2 | `/api/entities/search` | GET | Entities | Search entities |
| 3 | `/api/entities/{entityId}/auto-receipt` | GET | Entities | Get auto-receipt config |
| 4 | `/api/entities/{entityId}/auto-receipt` | POST | Entities | Update auto-receipt config |
| 5 | `/api/receipts/auto-submit` | POST | Receipts | Batch auto-submit behavioral receipts |
| 6 | `/api/trust/install-preflight` | POST | Software Trust | Software pre-action enforcement (experimental) |
| 7 | `/api/trust/zk-proof` | POST | Trust | Generate a commitment trust proof |
| 8 | `/api/trust/zk-proof` | GET | Trust | Verify a commitment trust proof |
| 9 | `/api/trust/domain-score/{entityId}` | GET | Trust | Domain-specific trust scores |
| 10 | `/api/needs/broadcast` | POST | Needs | Broadcast a need to the network |
| 11 | `/api/needs/{id}/claim` | POST | Needs | Claim a need |
| 12 | `/api/needs/{id}/complete` | POST | Needs | Complete a need |
| 13 | `/api/needs/{id}/rate` | POST | Needs | Rate a need fulfillment |
| 14 | `/api/feed` | GET | Needs | Live needs feed (SSE) |
| 15 | `/api/disputes/report` | POST | Disputes | Report an entity (lightweight dispute) |
| 16 | `/api/disputes/{disputeId}/adjudicate` | POST | Disputes | Operator adjudication of dispute |

---

## Classification: Non-Core / Legacy

Endpoints that are either legacy compatibility shims, marketing/waitlist
forms, or identity subsystem endpoints not required for the core trust loop.

| # | Endpoint | Method | Tag | Role |
|---|----------|--------|-----|------|
| 1 | `/api/score/{entityId}` | GET | Trust | Legacy compatibility score |
| 2 | `/api/score/{entityId}/history` | GET | Trust | Legacy score history |
| 3 | `/api/stats` | GET | System | Public proof metrics |
| 4 | `/api/leaderboard` | GET | Trust | Entity leaderboard |
| 5 | `/api/commit/keys` | GET | Commits | Public signing keys |
| 6 | `/api/operators/apply` | POST | Operations | Operator application form |
| 7 | `/api/inquiries` | POST | Operations | Partner/investor inquiry form |
| 8 | `/api/waitlist` | POST | Operations | Waitlist registration |
| 9 | `/api/identity/*` (7 endpoints) | Various | Identity | EP-IX identity bindings, continuity, principals |
| 10 | Page routes (`/`, `/quickstart`, `/apply`, `/operators`) | GET | -- | Next.js page routes (not API) |

Note: The 7 identity endpoints (`/api/identity/bind`, `/api/identity/verify`,
`/api/identity/continuity`, `/api/identity/continuity/challenge`,
`/api/identity/continuity/resolve`, `/api/identity/principal/{id}`,
`/api/identity/principal/{id}/agents`,
`/api/identity/principal/{id}/delegation-judgment`,
`/api/identity/lineage/{entityId}`) are part of EP-IX, which is an extension
specification. They may graduate to protocol-essential as EP-IX matures.

---

## Recommendations

### For the Protocol Spec

The protocol specification (EP-CORE-RFC, PROTOCOL-STANDARD) should reference
**only the 17 protocol-essential endpoints**. This is the "trust substrate"
that any conforming implementation must provide.

An integrator building against the EP protocol needs:
- 1 policy endpoint (read the policy registry)
- 5 handshake endpoints (initiate, present, verify, get, revoke)
- 5 commit endpoints (issue, verify, get, revoke, receipt)
- 1 trust evaluation endpoint
- 1 trust gate endpoint
- 1 trust profile endpoint (read)
- 1 delegation endpoint (create)
- 1 delegation verification endpoint

### For the Product API

The remaining endpoints should be documented as the **EP Product API** -- useful
for building applications on EP but not required for protocol conformance.
These include entity management, needs marketplace, auto-receipts, ZK proofs,
and the SSE feed.

### For the Admin API

The 5 operator-essential endpoints should be documented as the **EP Admin API**,
clearly marked as infrastructure-only. These should never appear in an SDK's
public surface.

### Deprecation Candidates

- `/api/score/{entityId}` and `/api/score/{entityId}/history` are explicitly
  marked as legacy in the OpenAPI spec. They should be removed in a future
  major version.
- `/api/leaderboard` and `/api/stats` are marketing/dashboard surfaces with
  no protocol function.

---

## OpenAPI Tag Mapping

| OpenAPI Tag | Classification | Action |
|-------------|---------------|--------|
| Trust | Protocol-Essential (evaluate, gate, profile) + Product (zk-proof, domain-score) + Legacy (score, leaderboard) | Split tag |
| Handshake | Protocol-Essential | Keep |
| Commits | Protocol-Essential | Keep |
| Policies | Protocol-Essential | Keep |
| Delegations | Protocol-Essential + Trust-Adjacent | Keep |
| Receipts | Trust-Adjacent + Product | Split tag |
| Disputes | Trust-Adjacent + Product | Split tag |
| Entities | Product | Move out of protocol spec |
| Needs | Product | Move out of protocol spec |
| Software Trust | Product | Move out of protocol spec |
| Identity | Non-Core (EP-IX extension) | Separate extension spec |
| Operations | Non-Core | Move out of protocol spec |
| System | Operator-Essential | Move to admin spec |
| Internal | Operator-Essential | Move to admin spec |

The Trust tag is the worst offender -- it mixes protocol-essential endpoints
(evaluate, gate, profile) with product surfaces (zk-proof, domain-score) and
legacy endpoints (score, leaderboard). Splitting this tag would immediately
reduce the perceived API surface in the protocol spec.
