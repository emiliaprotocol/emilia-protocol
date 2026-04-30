# Credential Rotation Checklist

**Status:** PENDING — do these in order, do them today.
**Why:** Two credentials leaked in conversation transcript during the
2026-04-26 Supabase wipe + npm publish work. Both are valid until
rotated.

---

## 1. Supabase database password

**Leaked value:** redacted — appears in the 2026-04-26 conversation
transcript when the Supabase wipe + re-migration was being driven via
the CLI. The literal value is **NOT** stored in this file. Pull it
from your password manager or the original transcript if you need to
identify which credential to revoke.
**Project:** `xmiiwehtivksdjbultym` (EMILIA Protocol production)

### Steps
1. Open https://supabase.com/dashboard/project/xmiiwehtivksdjbultym/settings/database
2. Click "Reset database password"
3. Generate a new password using a password manager (≥24 chars, no
   reused fragments). Store in 1Password under "EMILIA Protocol — DB".
4. Update the new password in any local `.env.local` file:
   ```bash
   cd /Users/imanschrock/Documents/GitHub.nosync/emilia-protocol
   vercel env pull .env.local --yes
   # Verify EP_DATABASE_URL or POSTGRES_URL contains the new password
   ```
5. Update Vercel project env if the connection string includes the
   password directly:
   ```bash
   # If using a URL with embedded password, regenerate it
   echo "postgres://postgres.xmiiwehtivksdjbultym:NEW_PW@aws-...:5432/postgres" \
     | vercel env add POSTGRES_URL production
   ```
6. Trigger a redeploy to pick up the new env var:
   ```bash
   git commit --allow-empty -m "chore: rotate DB credentials"
   git push origin main
   ```
7. Verify the deployment goes READY and the API still works:
   ```bash
   curl https://emiliaprotocol.ai/api/healthz  # or any read endpoint
   ```

### Confirm done
- [ ] New password generated and stored in password manager
- [ ] Local `.env.local` updated
- [ ] Vercel production env updated
- [ ] Redeploy ran and went READY
- [ ] One real API read confirmed working post-rotation
- [ ] Mark this checklist complete in the next commit message

---

## 2. npm token

**Leaked value:** redacted — appears in the 2026-04-26 conversation
transcript inside an `.npmrc` paste during the
`@emilia-protocol/verify@1.0.0` publish work. The literal token is
**NOT** stored in this file. Use the npm dashboard to find and revoke
the most recent classic token in your account.
**Scope:** `@emilia-protocol/*` packages

### Steps
1. Open https://www.npmjs.com/settings/emiliaprotocol/tokens
2. Identify the leaked token by its creation date (around the 1.0.0
   publish on 2026-04-26) or by checking your local `~/.npmrc` for
   the `_authToken=` value, then matching that prefix on the dashboard.
3. Click "Revoke" → confirm.
4. Create a fresh **Granular Access Token** (NOT a classic token):
   - Name: `emilia-protocol-publish-2026-q2`
   - Expiration: 90 days
   - Permissions:
     - Packages: `@emilia-protocol/*` → Read and write
     - Organization: `emilia-protocol` → Read only
   - IP allowlist: leave empty (you publish from variable IPs)
   - 2FA: required for publish (already set)
5. Save the new token in 1Password under "EMILIA Protocol — npm".
6. If your local `~/.npmrc` has the leaked token, update it:
   ```bash
   # Confirm what's there
   grep '^//registry.npmjs.org' ~/.npmrc
   # Replace with the new token
   npm login --scope=@emilia-protocol --auth-type=web
   # OR manually:
   echo "//registry.npmjs.org/:_authToken=NEW_TOKEN_VALUE" >> ~/.npmrc
   ```

### Confirm done
- [ ] Old token revoked on npmjs.com
- [ ] New granular token created with 90-day expiry
- [ ] New token stored in password manager
- [ ] Local `~/.npmrc` updated
- [ ] Test: `npm whoami` returns `emiliaprotocol`
- [ ] Mark this checklist complete in the next commit message

---

## After both rotations

Send a one-line confirmation in our next message:

> "Rotated DB password and npm token; old credentials revoked."

That's the verification step that closes the audit finding.

---

## Why this isn't automated

Both rotations require either a 2FA prompt (npm) or a logged-in
admin session (Supabase) that I can't drive. They are one-time,
hand-driven, security-sensitive operations. The tradeoff of
automating them via stored API keys would create exactly the
class of secret EMILIA's protocol is designed to gate — that's the
wrong precedent to set.
