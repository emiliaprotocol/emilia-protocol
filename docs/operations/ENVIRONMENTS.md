# EMILIA Protocol -- Environment Configuration

## Environment Tiers

### Development (Local)

**Purpose**: Local development and testing.

**Characteristics**:
- `NODE_ENV=development`
- Supabase: local instance via `supabase start` or a dedicated dev project
- Rate limiting: in-memory fallback (does not persist across restarts, does not work across multiple instances)
- Commit signing: ephemeral key auto-generated if `EP_COMMIT_SIGNING_KEY` is not set
- Missing required env vars produce console warnings but do not block startup (`assertServerEnv` in `lib/env.js` logs instead of throwing)
- Write guard is active (same enforcement as production)
- `EP_AUTO_SUBMIT_SECRET`: if not set, auto-submit requests are rejected with 401

**Setup**:
```bash
cp .env.example .env.local
# Edit .env.local with your local Supabase credentials
npm run dev
```

### Staging

**Purpose**: Pre-production validation. Mirrors production configuration with a separate database.

**Characteristics**:
- `NODE_ENV=production` (to exercise production code paths)
- Separate Supabase project (never shares a database with production)
- Upstash Redis configured (separate instance from production)
- All secrets set to staging-specific values (never reuse production secrets)
- Cron jobs active (on Vercel preview deployments, crons do not run automatically)
- Blockchain anchoring: configured to `sepolia` testnet

**Key differences from production**:
- Separate `SUPABASE_SERVICE_ROLE_KEY` pointing to staging database
- Separate `EP_COMMIT_SIGNING_KEY` (commits signed in staging are not verifiable in production)
- Separate `UPSTASH_REDIS_REST_URL` (rate limit state is isolated)

### Production

**Characteristics**:
- `NODE_ENV=production`
- `assertServerEnv()` throws on missing required variables (hard failure)
- `EP_COMMIT_SIGNING_KEY` is required (fatal error if absent)
- `EP_COMMIT_SIGNING_KEYS` must be valid JSON if set (fatal error if malformed)
- Rate limiting: Upstash Redis (distributed across all serverless instances)
- Write-sensitive rate limit categories (`submit`, `dispute_write`, `register`, `anchor`) fail-closed if Redis is unavailable (return 503 rather than allowing unthrottled writes)
- Read rate limits fail-open if Redis is unavailable (availability over throttling)
- Blockchain anchoring: configured to production chain
- Cron jobs active via `vercel.json`

## Environment Variable Matrix

| Variable | Development | Staging | Production |
|---|---|---|---|
| `NODE_ENV` | `development` | `production` | `production` |
| `NEXT_PUBLIC_SUPABASE_URL` | Local/dev project | Staging project | Production project |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Dev anon key | Staging anon key | Production anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Dev service key | Staging service key | Production service key |
| `EP_AUTO_SUBMIT_SECRET` | Optional (rejects if unset) | Staging secret | Production secret |
| `CRON_SECRET` | Test value | Vercel-managed | Vercel-managed |
| `EP_COMMIT_SIGNING_KEY` | Optional (ephemeral) | Staging key | **Required** |
| `EP_COMMIT_SIGNING_KEYS` | Optional | Staging key map | Production key map |
| `UPSTASH_REDIS_REST_URL` | Optional (in-memory) | Staging Redis | Production Redis |
| `UPSTASH_REDIS_REST_TOKEN` | Optional | Staging token | Production token |
| `BASE_NETWORK` | `sepolia` | `sepolia` | `mainnet` or as configured |
| `EP_WALLET_PRIVATE_KEY` | Test wallet | Test wallet | Production wallet |
| `OPENAI_API_KEY` | Optional | Optional | Optional |
| `GITHUB_TOKEN` | Optional | Optional | Optional |
| `EP_API_KEY` | Optional | Optional | Optional |
| `EP_BASE_URL` | `http://localhost:3000` | Staging URL | `https://emiliaprotocol.ai` |

## Fail Modes by Environment

### Missing `SUPABASE_SERVICE_ROLE_KEY`

- **Development**: `getServiceClient()` throws `Missing Supabase environment variables`. Application starts but any API call that needs the database fails.
- **Production**: Same behavior. The health check reports `checks.database.status: "error"`.

### Missing `EP_COMMIT_SIGNING_KEY`

- **Development**: Ephemeral key generated. Commits are signed but not verifiable across restarts.
- **Production**: Fatal startup error. Application does not start.

### Missing `UPSTASH_REDIS_REST_URL`

- **Development**: Rate limiting uses in-memory sliding window. Works for a single process. State is lost on restart.
- **Production**: Same fallback, but rate limit state is per-serverless-instance. Effectively no global rate limiting. The health check reports `checks.rate_limiter.backend: "in_memory"`.

### Missing `EP_AUTO_SUBMIT_SECRET`

- **All environments**: `getAutoSubmitSecret()` returns `null`. Auto-submit requests are rejected with 401.

## Vercel Environment Variable Configuration

Set environment variables in the Vercel dashboard under Project Settings > Environment Variables. Use the scope selectors:

- **Production**: variables used only in production deployments
- **Preview**: variables used in staging/preview deployments
- **Development**: variables pulled via `vercel env pull .env.local`

Never store secrets in `.env.local` in version control. The `.gitignore` must include `.env*`.
