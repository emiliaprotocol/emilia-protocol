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
| `EP_AGENT_RECORD_CREATION_CAPABILITY` | Application-only Agent Record creation authorization; must match the private database capability | `earc1_` + 64 lowercase hex |
| `UPSTASH_REDIS_REST_URL` | Upstash Redis endpoint for distributed rate limiting | `https://xxxx.upstash.io` |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash Redis auth token | `AXxx...` |
| `NEXT_PUBLIC_APP_URL` | Canonical HTTPS origin used for redirects and emailed links; never derive these from request Host headers in production | `https://www.emiliaprotocol.ai` |
| `SSO_STATE_SECRET` | Independent random secret for tenant-bound SAML RelayState envelopes | 32+ random bytes |
| `SSO_SESSION_SECRET` | Independent random secret for authenticated SSO sessions | 32+ random bytes |
| `TRUST_DESK_SESSION_SECRET` | Independent random secret for Trust Desk reviewer sessions | 32+ random bytes |

### Optional

| Variable | Purpose | Default |
|---|---|---|
| `EP_COMMIT_SIGNING_KEYS` | JSON map of `kid` to base64 public keys for key rotation | `null` |
| `EP_API_KEY` | Platform-level API key | `''` |
| `EP_BASE_URL` | Base URL of this EP instance | `https://emiliaprotocol.ai` |
| `EP_AUTO_RECEIPT_URL` | URL for auto-receipt submission | `https://emiliaprotocol.ai` |
| `BASE_NETWORK` | Blockchain network for anchoring (`sepolia` or `mainnet`) | `sepolia` |
| `EP_WALLET_PRIVATE_KEY` | Wallet private key for blockchain anchoring | N/A |
| `EP_BLOCKCHAIN_SIGNING_MODE` | Blockchain transaction signer (`env`, `kms`, or `hsm`) | `env` |
| `EP_BLOCKCHAIN_SIGNING_KEY_ID` | Auditable external signer key id; required for `kms`/`hsm` | N/A |
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
- [ ] `EP_AGENT_RECORD_CREATION_CAPABILITY` is configured in Vercel and matches the one-way private database capability
- [ ] `NEXT_PUBLIC_APP_URL` is the canonical HTTPS production origin
- [ ] `SSO_STATE_SECRET`, `SSO_SESSION_SECRET`, and `TRUST_DESK_SESSION_SECRET` are distinct random production values
- [ ] `TRUST_DESK_INTERNAL_TOKEN` has been rotated if it ever appeared in a URL; store the current bootstrap outside repository and deployment logs
- [ ] Upstash Redis is configured (rate limiting falls back to in-memory without it, which does not work across serverless instances)
- [ ] Database schema is applied and append-only triggers are active on `protocol_events` and `handshake_events`
- [ ] `npm run check:protocol` passes (write-discipline CI enforcement)
- [ ] `npm run test:run` passes

### Deployment

For Agent Record and other forward-compatible database changes, deploy in this
order:

1. Generate the Agent Record creation capability in a secure operator context.
   It must be `earc1_` followed by 64 lowercase hexadecimal characters. Do not
   print it to build output, application logs, or public readiness responses.
2. Apply the forward-compatible Supabase migration first.
3. Using the same hosted non-superuser migration operator, call
   `public.configure_agent_record_creation_capability(secret)` as documented in
   [Agent Record creation capability](../AGENT-RECORD-CREATION-CAPABILITY.md).
   The migration grants that operator only this configuration RPC after
   removing every temporary `agent_record_store_owner` membership edge. Do not grant
   the private table, private helper, public configuration RPC, or base creator
   to `service_role`.
4. Verify the live database contract before application promotion: confirm the
   expected function signatures and grants, confirm direct execution of the
   base creator remains denied to `service_role`, and run the non-mutating
   capability and RPC contract checks.
5. Set the same value as `EP_AGENT_RECORD_CREATION_CAPABILITY` in the target
   Vercel environment alongside the signer, Supabase, and Upstash prerequisites.
6. Only after the database verification passes, promote or merge the Vercel
   application that calls the new contract. Vercel must also have the blocking
   deployment check below before any new production deployment is allowed to
   auto-alias.

This ordering keeps the old application compatible while the database moves
forward and prevents a new application from reaching RPCs that are not live yet.

### Required external Vercel production-alias gate

`vercel.json` cannot register project Deployment Checks. Production aliasing
remains unsafe until this external check exists in the linked Vercel project.
The GitHub Actions check-run name is intentionally unique and stable:
`emilia-production-schema-contract-v2`. Do not rename it without replacing the
Vercel configuration and branch-protection requirement in the same controlled
change.

From a directory linked to the intended Vercel project, first inspect and list;
then add exactly one blocking production check:

```bash
vercel project inspect
vercel project checks --format json
vercel project checks add \
  --check-name "emilia-production-schema-contract-v2" \
  --requires build-ready \
  --blocks deployment-alias \
  --targets production \
  --timeout 5000 \
  --source '{"kind":"git-provider","provider":"github","externalCheckName":"emilia-production-schema-contract-v2"}' \
  --format json
vercel project checks --blocks deployment-alias --format json
```

The equivalent API operation is `POST /v2/projects/{projectIdOrName}/checks`
with a team-scoped token that can manage the intended project:

```bash
curl --fail-with-body --request POST \
  --url "https://api.vercel.com/v2/projects/${VERCEL_PROJECT_ID}/checks?teamId=${VERCEL_TEAM_ID}" \
  --header "Authorization: Bearer ${VERCEL_TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{
    "name": "emilia-production-schema-contract-v2",
    "requires": "build-ready",
    "blocks": "deployment-alias",
    "targets": ["production"],
    "timeout": 5000,
    "source": {
      "kind": "git-provider",
      "provider": "github",
      "externalCheckName": "emilia-production-schema-contract-v2"
    }
  }'
```

Use the CLI path when possible because it resolves the already-linked project
and scope. Never paste token values into the command or repository. If creation
returns an ambiguous error, list checks before retrying so a duplicate is not
created. The resulting object must have `requires=build-ready`,
`blocks=deployment-alias`, `targets=["production"]`, `timeout=5000`, and the
exact GitHub source above. Also require
`emilia-production-schema-contract-v2` in GitHub rules for `main`. A Vercel
`Force Promote` bypasses Deployment Checks and requires an explicit incident
decision; it is not a normal release path.

GitHub Actions reruns retain the failed check run and create another attempt.
Vercel can therefore bind a redeploy of the same commit to the historical
failure even after the rerun succeeds. Preserve both results as audit evidence:
do not delete the Actions run or bypass the deployment check. Release a new
reviewed commit, or rotate this exact external check name together with the
workflow, Vercel project configuration, and GitHub rule.

Rotate the name fail-closed. Add the new Vercel check while the old check still
blocks production aliasing. Merge the reviewed workflow rename under the old
GitHub requirement; the first new production deployment may remain deliberately
unaliased. After the new check succeeds on `main`, replace the GitHub required
context with the v2 name, remove the old Vercel check by its inspected id, and
redeploy that exact reviewed commit so only the successful v2 verdict controls
aliasing:

```bash
vercel project checks --format json
vercel project checks remove "${OLD_VERCEL_CHECK_ID}"
vercel redeploy "${REVIEWED_DEPLOYMENT_ID}" --target production
vercel project checks --blocks deployment-alias --format json
```

Never delete the historical GitHub Actions run. If the GitHub rule cannot be
updated, keep the old Vercel check in place and leave the deployment unaliased;
do not create an unguarded transition window.

```bash
# Build
npm run build

# Deploy to Vercel
vercel --prod

# Or start locally
npm run start
```

### Post-Deployment Verification

1. **Readiness check**: `GET /api/health`

   Expected response:
   ```json
   { "status": "ready" }
   ```

   Verify:
   - HTTP status is `200`; any unavailable production dependency returns `503`
     with exactly `{ "status": "not_ready" }`.
   - The body contains no dependency, schema, count, latency, or secret detail.
   - `GET /api/live` separately returns `200` with exactly
     `{ "status": "live" }` and proves process liveness only.

2. **Entity registration**: `POST /api/entities/register` with a test entity. Confirm a `201` response and that an `ep_live_` API key is returned.

3. **Write discipline**: Attempt a direct insert on a trust table through a route handler. The write guard must throw `WRITE_DISCIPLINE_VIOLATION`.

4. **Rate limiting**: Send requests exceeding the configured limit for any category. Confirm `429` responses with `X-RateLimit-*` headers.

5. **Cron execution**: Manually trigger `/api/blockchain/anchor` and `/api/cron/expire` to verify they complete without errors.

## Health Check Endpoint

**`GET /api/health`** -- unauthenticated readiness. Production returns `200`
only when the signer, durable limiter, Supabase configuration, matching creation
capability, and every Agent Record RPC probe pass. False, missing, malformed,
or thrown checks return a detail-free `503`. Responses are never cached.

**`GET /api/live`** -- unauthenticated process-only liveness. It does not query
the database and must not be used to decide whether a deployment may receive
traffic.

## Rollback Procedure

1. Revert to the previous Vercel deployment via the Vercel dashboard or `vercel rollback`.
2. Retain the already-applied forward-compatible database migration. Application rollback does not roll back the Supabase schema.
3. Do not invent or apply an Agent Record rollback migration. There is no destructive Agent Record down migration; use a separately reviewed forward repair if the live database contract itself needs correction.
4. Verify via `/api/health` that the rolled-back application is healthy against the retained schema.
5. Protocol events are append-only and cannot be rolled back. If a bad state was materialized, use the reconstitution script: `npm run reconstitute` to replay events and rebuild projections.
