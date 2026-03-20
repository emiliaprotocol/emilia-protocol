# EMILIA Protocol -- Deployment Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Node.js | >= 18.x | Required for `crypto.randomUUID()` and native fetch |
| npm | >= 9.x | Ships with Node 18+ |
| Supabase project | N/A | Postgres database with Row Level Security support |
| Vercel account | N/A | Production deployment target (or any Node.js hosting) |
| Upstash Redis | N/A | Required for production rate limiting; optional in dev |

## Environment Variables

All environment variables are accessed through `lib/env.js`. No other file reads `process.env` directly (except `next.config.js`).

### Required in All Environments

| Variable | Purpose | Example |
|---|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL | `https://xxxx.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side Supabase client (never exposed to browser) | `eyJhbGciOiJI...` |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Client-side Supabase key (public, RLS-enforced) | `eyJhbGciOiJI...` |

### Required in Production

| Variable | Purpose | Example |
|---|---|---|
| `EP_AUTO_SUBMIT_SECRET` | Shared secret for machine-to-machine `/api/receipts/auto-submit` auth | 64+ char random string |
| `CRON_SECRET` | Vercel Cron authentication token | Auto-set by Vercel |
| `EP_COMMIT_SIGNING_KEY` | Base64-encoded 32-byte Ed25519 seed for commit signing | Base64 string |
| `UPSTASH_REDIS_REST_URL` | Upstash Redis endpoint for distributed rate limiting | `https://xxxx.upstash.io` |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash Redis auth token | `AXxx...` |

### Optional

| Variable | Purpose | Default |
|---|---|---|
| `EP_COMMIT_SIGNING_KEYS` | JSON map of `kid` to base64 public keys for key rotation | `null` |
| `EP_API_KEY` | Platform-level API key | `''` |
| `EP_BASE_URL` | Base URL of this EP instance | `https://emiliaprotocol.ai` |
| `EP_AUTO_RECEIPT_URL` | URL for auto-receipt submission | `https://emiliaprotocol.ai` |
| `BASE_NETWORK` | Blockchain network for anchoring (`sepolia` or `mainnet`) | `sepolia` |
| `EP_WALLET_PRIVATE_KEY` | Wallet private key for blockchain anchoring | N/A |
| `OPENAI_API_KEY` | OpenAI key (if AI features are enabled) | `null` |
| `GITHUB_TOKEN` | GitHub token for CI/integration features | `null` |

## Environment Setup

### 1. Clone and Install

```bash
git clone https://github.com/your-org/emilia-protocol.git
cd emilia-protocol
npm install
```

### 2. Create `.env.local`

```bash
# Supabase (required)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Auto-submit (required for production)
EP_AUTO_SUBMIT_SECRET=your-64-char-random-secret

# Cron (set automatically by Vercel in production)
CRON_SECRET=your-cron-secret

# Commit signing (required for production; auto-generated in dev)
EP_COMMIT_SIGNING_KEY=base64-encoded-32-byte-ed25519-seed

# Rate limiting (required for production; falls back to in-memory in dev)
UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-redis-token
```

### 3. Validate Environment

In production, `assertServerEnv()` from `lib/env.js` throws on missing required variables. In development, it logs warnings but allows startup:

```js
import { assertServerEnv } from '@/lib/env';

assertServerEnv({
  required: [
    'NEXT_PUBLIC_SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
  ],
});
```

## Database Setup

EP uses Supabase (Postgres). The schema includes these trust-bearing tables that are protected by the write guard (`lib/write-guard.js`):

- `receipts`, `commits`, `disputes`, `trust_reports`
- `protocol_events` (append-only event log)
- `handshakes`, `handshake_parties`, `handshake_presentations`
- `handshake_bindings`, `handshake_results`, `handshake_policies`
- `handshake_events` (append-only), `handshake_consumptions`

Supporting tables (not write-guarded):
- `entities`, `api_keys`

Apply schema through the Supabase dashboard SQL editor or CLI. The `protocol_events` and `handshake_events` tables must have database triggers that prevent UPDATE and DELETE operations (append-only enforcement).

## Cron Jobs

Defined in `vercel.json`:

```json
{
  "crons": [
    {
      "path": "/api/blockchain/anchor",
      "schedule": "0 */6 * * *"
    },
    {
      "path": "/api/cron/expire",
      "schedule": "0 * * * *"
    }
  ]
}
```

| Job | Schedule | Purpose |
|---|---|---|
| `/api/blockchain/anchor` | Every 6 hours | Anchors protocol event hashes to Base L2 blockchain |
| `/api/cron/expire` | Every hour | Expires stale handshake bindings and timed-out disputes |

Both endpoints are rate-limited to the `anchor` category (1 request per 6 hours).

## Deployment Checklist

### Pre-Deployment

- [ ] All required environment variables are set (see matrix above)
- [ ] `EP_COMMIT_SIGNING_KEY` is set (fatal error in production if missing)
- [ ] `EP_COMMIT_SIGNING_KEYS` is valid JSON if set (fatal error in production if malformed)
- [ ] Upstash Redis is configured (rate limiting falls back to in-memory without it, which does not work across serverless instances)
- [ ] Database schema is applied and append-only triggers are active on `protocol_events` and `handshake_events`
- [ ] `npm run check:protocol` passes (write-discipline CI enforcement)
- [ ] `npm run test:run` passes

### Deployment

```bash
# Build
npm run build

# Deploy to Vercel
vercel --prod

# Or start locally
npm run start
```

### Post-Deployment Verification

1. **Health check**: `GET /api/health`

   Expected response:
   ```json
   {
     "status": "healthy",
     "protocol_version": "EP/1.1-v2",
     "timestamp": "2026-03-20T...",
     "uptime_check_ms": 150,
     "checks": {
       "database": { "status": "ok", "latency_ms": 120, "entities": 42, "receipts": 300, "active_disputes": 2 },
       "rate_limiter": { "status": "ok", "backend": "upstash_redis" },
       "anchoring": { "status": "configured", "chain": "base_l2" }
     },
     "surfaces": { ... }
   }
   ```

   Verify:
   - `status` is `"healthy"` (not `"degraded"`)
   - `checks.database.status` is `"ok"`
   - `checks.rate_limiter.backend` is `"upstash_redis"` in production (not `"in_memory"`)
   - `checks.anchoring.status` is `"configured"` if blockchain anchoring is enabled

2. **Entity registration**: `POST /api/entities/register` with a test entity. Confirm a `201` response and that an `ep_live_` API key is returned.

3. **Write discipline**: Attempt a direct insert on a trust table through a route handler. The write guard must throw `WRITE_DISCIPLINE_VIOLATION`.

4. **Rate limiting**: Send requests exceeding the configured limit for any category. Confirm `429` responses with `X-RateLimit-*` headers.

5. **Cron execution**: Manually trigger `/api/blockchain/anchor` and `/api/cron/expire` to verify they complete without errors.

## Health Check Endpoint

**`GET /api/health`** -- no authentication required.

Checks performed:
- Database connectivity and query latency
- Entity, receipt, and active dispute counts
- Rate limiter backend status (Upstash Redis vs in-memory fallback)
- Blockchain anchoring configuration status

Returns `200` with `status: "healthy"` or `status: "degraded"` if any check fails. The endpoint itself never returns a non-200 status unless the response assembly fails (500).

## Rollback Procedure

1. Revert to the previous Vercel deployment via the Vercel dashboard or `vercel rollback`.
2. If a database migration was applied, apply the corresponding rollback migration.
3. Verify via `/api/health` that the rolled-back instance is healthy.
4. Protocol events are append-only and cannot be rolled back. If a bad state was materialized, use the reconstitution script: `npm run reconstitute` to replay events and rebuild projections.
