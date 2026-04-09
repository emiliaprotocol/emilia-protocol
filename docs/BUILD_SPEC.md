# Emilia Protocol — Build Specification
**Version:** 1.0  
**Status:** Production-ready for regulated-industry deployment  
**Last Updated:** 2026-04-07

---

## 1. What We Are Building

Emilia Protocol (EP) is a **trust enforcement infrastructure layer** for AI agents, automated systems, and human-AI workflows. It is not a product feature — it is a protocol. Operators embed EP into their own systems to give every consequential action a verifiable, tamper-evident trust record.

### The Four-Product Protocol Stack

```
┌─────────────────────────────────────────────────────┐
│  EP EYE       Observes and classifies agent behavior │
│               OBSERVE → SHADOW → ENFORCE lifecycle   │
├─────────────────────────────────────────────────────┤
│  EP HANDSHAKE Cryptographic consent ceremony         │
│               7-property binding: mode, parties,     │
│               policy, action, hash, binding, expiry  │
├─────────────────────────────────────────────────────┤
│  EP SIGNOFF   Named human ownership of outcomes      │
│               Challenge → Attest → Consume lifecycle │
├─────────────────────────────────────────────────────┤
│  EP COMMIT    Atomic, immutable action close         │
│               No partial states. Sealed on write.   │
└─────────────────────────────────────────────────────┘
```

---

## 2. Technical Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Framework | Next.js (App Router) | All routes under `app/api/` |
| Runtime | Node.js 20 LTS | Edge runtime not used (crypto deps) |
| Database | Supabase (Postgres 15) | Project: `xmiiwehtivksdjbultym` |
| Deployment | Vercel | Production branch: `main` |
| Blockchain | Base L2 (Coinbase) | Merkle root anchoring, ~$0.60/mo |
| Auth | Custom API key scheme | `ep_live_*` / `ep_test_*` prefixed keys |
| Crypto | Node.js `crypto` + HMAC-SHA256 | Commitment proofs, timing-safe compares |

---

## 3. API Surface

### Public Endpoints (no auth)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/trust/zk-proof?proof_id=ep_zkp_...` | Verify commitment proof |
| POST | `/api/partner` | Partner inquiry form |
| POST | `/api/investor` | Investor inquiry form |
| POST | `/api/waitlist` | Waitlist signup |

### Authenticated Endpoints (`Bearer ep_live_...`)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/handshake` | Create handshake |
| GET | `/api/handshake/[id]` | Get handshake |
| POST | `/api/handshake/[id]/verify` | Verify handshake |
| POST | `/api/handshake/[id]/present` | Add presentation |
| POST | `/api/handshake/[id]/consume` | Consume handshake |
| POST | `/api/trust/zk-proof` | Generate commitment proof |
| GET | `/api/trust/score/[entityId]` | Get trust score |
| GET | `/api/identity/principal/[principalId]` | Get principal |
| GET | `/api/identity/lineage/[entityId]` | Get entity lineage |
| POST | `/api/disputes` | File dispute |
| POST | `/api/disputes/[id]/adjudicate` | Adjudicate dispute |
| POST | `/api/eye/observe` | Submit Eye observation |
| POST | `/api/eye/advisory` | Issue Eye advisory |
| POST | `/api/signoff` | Create signoff |
| POST | `/api/signoff/[id]/attest` | Attest signoff |

### Cron / Internal (Bearer cron secret)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/disputes/resolve` | Batch dispute resolution |
| POST | `/api/disputes/appeal/resolve` | Batch appeal resolution |
| POST | `/api/anchor` | Batch Merkle anchoring to Base L2 |

---

## 4. Data Architecture

### Entity Model
```
entities                 ← root trust subject (agent, human, service)
  ├── api_keys           ← authenticates API calls → resolves entity_id
  ├── principals         ← identity binding (DID, cert, email)
  ├── identity_bindings  ← verifiable credential links
  └── trust_reports      ← computed trust score snapshots

receipts                 ← immutable action record
  ├── anchor_batches     ← Merkle batch grouping
  └── merkle proof       ← proof of inclusion in batch
```

### Handshake Lifecycle
```
handshakes (status: pending → active → verified | rejected | expired | revoked)
  ├── handshake_parties       ← party set with roles
  ├── handshake_bindings      ← cryptographic binding hash
  ├── handshake_presentations ← VC/claim presentations
  ├── handshake_policies      ← policy evaluation results
  ├── handshake_results       ← verification outcome
  ├── handshake_events        ← full audit event log
  └── handshake_consumptions  ← one-time consumption record
```

### Write Guard
All writes to trust-bearing tables go through `lib/write-guard.js` — a Proxy-based enforcement layer that rejects non-service-role writes to `TRUST_TABLES`:
```
receipts, handshakes, handshake_bindings, handshake_consumptions,
handshake_parties, handshake_events, handshake_results,
signoff_attestations, signoff_consumptions, signoff_events,
eye_observations, eye_advisories, trust_reports, anchor_batches,
protocol_events, audit_events, zk_proofs
```

---

## 5. Security Model

### Authentication
- All API access via `Bearer ep_live_*` / `Bearer ep_test_*` keys
- Key hash stored in `api_keys` table (never plaintext)
- Key → entity binding resolved by `resolve_authenticated_actor()` SECURITY DEFINER function
- Timing-safe comparison via `crypto.timingSafeEqual()` for all secret compares (cron auth, webhook signatures)

### Authorization
- Entity can only act on its own resources (checked at route layer)
- Operator flag for cross-entity admin operations
- Tenant isolation enforced at application layer via `tenant_id` filters

### Database Security
- RLS enabled on all 50 tables
- `service_role` bypass policy on all tables (API uses service_role exclusively)
- `anon` INSERT-only on `partner_inquiries`, `investor_inquiries` (lead capture)
- All `SECURITY DEFINER` functions pinned to `SET search_path = public`
- All high-contention operations use atomic RPCs with `FOR UPDATE` locks (migrations 074, 075)

### Cryptographic Anchoring
- Receipt hashes: SHA-256
- Commitment proofs: HMAC-SHA256 Merkle tree over receipt set
- Batch anchoring: Merkle root posted to Base L2 as calldata (`EP:v1:{batchId}:{root}`)
- Anyone can independently verify any receipt's inclusion via `verifyMerkleProof()`

---

## 6. Environment Variables

### Required for Production
```
# Supabase
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Blockchain anchoring
EP_WALLET_PRIVATE_KEY=        # hex, no 0x prefix; Base L2 signing key
EP_BLOCKCHAIN_NETWORK=mainnet # or 'testnet' for Base Sepolia

# Operator auth (per-operator tokens replace shared CRON_SECRET)
EP_OPERATOR_KEYS=             # JSON map: {"operator_id": "hex_secret", ...}
CRON_SECRET=                  # DEPRECATED — legacy shared secret, still accepted for migration

# App
NEXT_PUBLIC_APP_URL=
```

### Rotation Policy
- `SUPABASE_SERVICE_ROLE_KEY`: Rotate on any suspected compromise. Rotates in Supabase dashboard → API settings.
- `EP_WALLET_PRIVATE_KEY`: Rotate by generating new keypair, funding new address, updating env. Old key should be zeroed.
- `CRON_SECRET`: Rotate any time; update simultaneously in Vercel env and Vercel cron config.

---

## 7. Database Migration History

| # | Name | Purpose |
|---|------|---------|
| 001–073 | (historical) | Schema bootstrapping, protocol tables, indexing |
| 074 | `consume_handshake_atomic` | Atomic TOCTOU-safe handshake consumption RPC |
| 075 | `bulk_update_receipt_anchors` | Replace N+1 anchor loop with single atomic RPC |
| 076 | `rls_policies_all_tables` | Service_role bypass + anon INSERT policies on all 39 unprotected tables |
| 077 | `harden_function_search_paths` | Pin `search_path = public` on all 27 SECURITY DEFINER functions |
| 078 | `add_entity_keypair_columns` | Ed25519 `public_key` + `private_key_encrypted` columns on entities |

---

## 8. Deployment Architecture

```
GitHub (main branch)
    │
    ▼
Vercel (auto-deploy on push)
    ├── Next.js build
    ├── Serverless functions (Node.js 20)
    └── Cron jobs (via vercel.json)
         ├── /api/anchor       — every 5 minutes
         ├── /api/disputes/resolve — every hour
         └── /api/disputes/appeal/resolve — every hour

Supabase (xmiiwehtivksdjbultym)
    ├── Postgres 15 (primary)
    ├── Realtime (not used)
    └── Storage (not used)

Base L2 (Coinbase)
    └── Merkle root calldata transactions
        └── Verifiable at basescan.org/tx/{hash}
```

---

## 9. Regulated-Industry Readiness

### What Is Done
- [x] RLS on all 50 tables with explicit policies (migration 076)
- [x] All SECURITY DEFINER functions search_path-hardened (migration 077)
- [x] Atomic RPC for handshake consumption — eliminates TOCTOU race (migration 074)
- [x] Atomic bulk anchor update — eliminates partial-batch corruption (migration 075)
- [x] Timing-safe secret comparison on all cron/webhook auth
- [x] Fail-closed tenant isolation in event explorer
- [x] Authentication required on all identity endpoints
- [x] Entity-bound proof generation (cannot generate proofs for other entities)
- [x] Write guard enforced on all trust-bearing tables
- [x] Blockchain anchoring throws (not silently skips) in production without key

### What Remains Before Regulated Deployment
- [ ] **Credential rotation**: Rotate `SUPABASE_SERVICE_ROLE_KEY`, `CRON_SECRET`, `EP_WALLET_PRIVATE_KEY` — must be done manually by operator
- [ ] **Third-party security audit**: Recommend Trail of Bits or Cure53 before SOC 2 / HIPAA claims
- [ ] **Operator credential redesign**: Replace shared `CRON_SECRET` with per-operator signed tokens
- [ ] **Rate limiting**: Add per-key rate limiting at Vercel edge or middleware layer
- [ ] **SIEM integration**: Forward `audit_events` and `protocol_events` to a SIEM (Splunk, Datadog, etc.)
- [ ] **Disaster recovery drill**: Test backup restore and point-in-time recovery on EP Supabase project
- [ ] **Penetration test**: Targeted test of the handshake ceremony and commitment proof API

### Compliance Posture
| Control | Status | Notes |
|---------|--------|-------|
| Access control | Partial | RLS + service_role; operator MFA pending |
| Audit logging | Yes | `audit_events` + `handshake_events` tables |
| Data at rest | Yes | Supabase encrypted storage |
| Data in transit | Yes | TLS enforced (Vercel + Supabase) |
| Cryptographic integrity | Yes | SHA-256 + Merkle + Base L2 anchoring |
| Credential management | Partial | Env vars set; rotation policy not automated |
| Incident response | No | No runbook, no PagerDuty/on-call |
| Third-party audit | No | Scheduled; not yet complete |

---

## 10. Key Invariants (Never Break These)

1. **A handshake can only be consumed once.** Enforced by `consume_handshake_atomic()` with `FOR UPDATE` lock + unique constraint on `handshake_consumptions.handshake_id`.

2. **An entity can only generate commitment proofs for itself.** Enforced at API layer: `auth.entity.entity_id !== entity_id → 403`.

3. **Trust table writes are service_role only.** Enforced by write-guard proxy; any anon/authenticated write attempt is rejected before hitting Supabase.

4. **Blockchain anchoring must not silently skip in production.** `anchorToBase()` throws if `EP_WALLET_PRIVATE_KEY` is missing in production — never returns `{ skipped: true }`.

5. **Commitment proofs never reveal the receipt set.** `GET /api/trust/zk-proof` deliberately omits `commitment_root` and `salt`. Verifiers learn only the claim verdict.

6. **Tenant isolation is fail-closed.** `getTimeline()` and all event queries throw on missing or mismatched `tenant_id` — they do not fall back to returning data.
