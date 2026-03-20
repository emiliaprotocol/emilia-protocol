# EMILIA Protocol -- Key Management

## Key Inventory

EP uses five categories of secrets. Each has different generation, storage, and rotation requirements.

### 1. Entity API Keys (`ep_live_` prefix)

**Purpose**: Authenticate entities (users, services, organizations) making API requests.

**Format**: `ep_live_` followed by 64 hex characters (32 random bytes).

**Generation** (`lib/supabase.js`):
```js
const key = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
const hash = crypto.createHash('sha256').update(key).digest('hex');
// Store hash in api_keys table, return plaintext key to entity once
```

**Storage**:
- The plaintext key is returned to the entity exactly once at registration time.
- Only the SHA-256 hash is stored in the `api_keys` table (`key_hash` column).
- The first 16 characters of the key are used as a rate-limit identity prefix in middleware.

**Authentication flow** (`authenticateRequest` in `lib/supabase.js`):
1. Extract `Bearer ep_...` from the `Authorization` header.
2. Compute `SHA-256(key)` and look up in `api_keys.key_hash`.
3. Reject if no match (`key_not_found`, 401).
4. Reject if `revoked_at` is set (`key_revoked`, 403).
5. Reject if the linked entity's `status` is not `active` (`entity_inactive`, 403).
6. Update `last_used_at` on the key record.
7. Return the entity object and permissions.

**Rotation**:
1. Issue a new API key for the entity via the registration endpoint.
2. Update the entity's integration to use the new key.
3. Revoke the old key by setting `revoked_at` on the `api_keys` record.
4. The old key will receive `403 key_revoked` on subsequent use.

### 2. Supabase Service Role Key (`SUPABASE_SERVICE_ROLE_KEY`)

**Purpose**: Server-side database access with full privileges, bypassing Row Level Security.

**Where it is used**: `lib/supabase.js` -- `getServiceClient()` creates a Supabase client with this key.

**Security constraints**:
- NEVER exposed to the browser. It is not prefixed with `NEXT_PUBLIC_`.
- Only `protocolWrite()` and `getServiceClient()` use this key for trust-bearing writes.
- Route handlers use `getGuardedClient()` from `lib/write-guard.js`, which proxies the service client and blocks mutations on trust tables.

**Rotation**:
1. Generate a new service role key in the Supabase dashboard (Settings > API).
2. Update `SUPABASE_SERVICE_ROLE_KEY` in Vercel environment variables.
3. Redeploy. The old key is invalidated by Supabase immediately.
4. Verify via `/api/health` that `checks.database.status` is `"ok"`.

### 3. Auto-Submit Machine Secret (`EP_AUTO_SUBMIT_SECRET`)

**Purpose**: Authenticates machine-to-machine requests to `/api/receipts/auto-submit`. This endpoint accepts high-volume automated receipt submissions from trusted integrations.

**Where it is used**: `lib/env.js` -- `getAutoSubmitSecret()`.

**Security constraints**:
- Must be at least 64 characters of cryptographic randomness.
- Transmitted in request headers, never in query strings or request bodies.
- In production, a missing secret causes all auto-submit requests to be rejected with 401.
- In development, a missing secret also causes rejection (no fallback).

**Rotation**:
1. Generate a new secret: `openssl rand -hex 64`.
2. Update `EP_AUTO_SUBMIT_SECRET` in Vercel environment variables.
3. Update all machine clients that call `/api/receipts/auto-submit` to use the new secret.
4. Redeploy. There is no grace period -- the old secret stops working immediately.

### 4. Cron Secret (`CRON_SECRET`)

**Purpose**: Authenticates Vercel Cron Job requests to `/api/blockchain/anchor` and `/api/cron/expire`.

**Where it is used**: `lib/env.js` -- `getCronSecret()`.

**How it works**: Vercel automatically sets `CRON_SECRET` and sends it as the `Authorization: Bearer <CRON_SECRET>` header on cron invocations. The cron route handler validates this header.

**Rotation**: Managed by Vercel. If you need to rotate, regenerate in the Vercel dashboard under project settings.

### 5. Commit Signing Key (`EP_COMMIT_SIGNING_KEY`)

**Purpose**: Ed25519 signing key for cryptographically signing trust commitments.

**Format**: Base64-encoded 32-byte Ed25519 seed.

**Where it is used**: `lib/env.js` -- `getCommitSigningConfig()`.

**Behavior by environment**:
- **Production**: `EP_COMMIT_SIGNING_KEY` is REQUIRED. Its absence is a fatal startup error.
- **Development/Test**: If absent, an ephemeral key is generated for convenience.

**Key rotation with `EP_COMMIT_SIGNING_KEYS`**:

The `EP_COMMIT_SIGNING_KEYS` variable supports key rotation by maintaining a map of key IDs to public keys:

```json
{
  "ep-signing-key-1": "base64-public-key-1",
  "ep-signing-key-2": "base64-public-key-2"
}
```

Rotation procedure:
1. Generate a new Ed25519 keypair.
2. Add the new public key to `EP_COMMIT_SIGNING_KEYS` with a new `kid`.
3. Update `EP_COMMIT_SIGNING_KEY` to the new private seed.
4. Redeploy. New commits are signed with the new key.
5. Old commits remain verifiable via the old public key in `EP_COMMIT_SIGNING_KEYS`.
6. After a grace period (e.g., 90 days), remove the old key from `EP_COMMIT_SIGNING_KEYS`.

**If `EP_COMMIT_SIGNING_KEYS` contains invalid JSON in production**, the application throws a fatal error at startup.

## Compromise Response Procedures

### API Key Compromised (`ep_live_*`)

1. **Immediate**: Set `revoked_at` on the compromised key's `api_keys` record.
2. The entity will receive `403 key_revoked` on subsequent requests.
3. Issue a new key for the entity.
4. Review `protocol_events` for any unauthorized writes made with the compromised key's entity.
5. If unauthorized trust-changing writes occurred, file disputes against affected receipts.

### Service Role Key Compromised (`SUPABASE_SERVICE_ROLE_KEY`)

**Severity: Critical** -- this key bypasses all Row Level Security.

1. **Immediate**: Rotate the key in the Supabase dashboard. This invalidates the old key instantly.
2. Update `SUPABASE_SERVICE_ROLE_KEY` in Vercel and redeploy.
3. Audit the `protocol_events` table for any events that lack corresponding legitimate API requests.
4. Check for direct database modifications that bypassed `protocolWrite()` -- these would not appear in `protocol_events`.
5. Run `npm run reconstitute` to rebuild projections from the event log and compare against current state.

### Auto-Submit Secret Compromised (`EP_AUTO_SUBMIT_SECRET`)

1. **Immediate**: Rotate the secret in Vercel environment variables and redeploy.
2. Update all legitimate machine clients with the new secret.
3. Review recent auto-submit receipts in `protocol_events` for anomalous volumes or patterns.
4. If fraudulent receipts were submitted, dispute them through the standard dispute process.

### Commit Signing Key Compromised (`EP_COMMIT_SIGNING_KEY`)

1. **Immediate**: Generate a new Ed25519 keypair.
2. Update `EP_COMMIT_SIGNING_KEY` to the new seed.
3. Add the new public key to `EP_COMMIT_SIGNING_KEYS`.
4. Remove the compromised public key from `EP_COMMIT_SIGNING_KEYS`.
5. Redeploy.
6. All commits signed with the compromised key can no longer be verified as trusted.
7. Review all commits signed during the compromise window and consider revocation.

## Secret Generation Commands

```bash
# API key (done programmatically, but for reference)
node -e "console.log('ep_live_' + require('crypto').randomBytes(32).toString('hex'))"

# Auto-submit secret
openssl rand -hex 64

# Ed25519 signing key (32-byte seed, base64)
openssl rand -base64 32

# Cron secret (managed by Vercel, but for local testing)
openssl rand -hex 32
```
