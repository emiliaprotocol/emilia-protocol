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
**Project:** EMILIA Protocol production Supabase project (`<project-ref>`)

### Steps
1. Open `https://supabase.com/dashboard/project/<project-ref>/settings/database`
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
   echo "postgres://postgres.<project-ref>:NEW_PW@aws-...:5432/postgres" \
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

## 2. npm write credentials

**Leaked value:** redacted — appears in the 2026-04-26 conversation
transcript inside an `.npmrc` paste during the
`@emilia-protocol/verify@1.0.0` publish work. The literal token is
**NOT** stored in this file. Use the npm dashboard to find and revoke
the most recent classic token in your account.
**Scope:** `@emilia-protocol/*` packages

Package publication uses GitHub Actions OIDC trusted publishing and the
owner-approved workflow described in `NPM-PUBLISH-CHECKLIST.md`. A local or CI
write token is not a supported fallback.

### Steps
1. Open https://www.npmjs.com/settings/emiliaprotocol/tokens
2. Identify the leaked token by its creation date (around the 1.0.0 publish on
   2026-04-26). Also identify every other active token with package-write or
   organization-write permission; trusted publishing makes those credentials
   unnecessary for releases.
3. Revoke the leaked token and every unneeded write-capable token. Do not create
   a replacement publish token.
4. Remove any registry token from the user npm configuration:
   ```bash
   npm config delete //registry.npmjs.org/:_authToken --location=user
   ```
5. Read back all seven package trusted-publisher mappings with the commands in
   `NPM-PUBLISH-CHECKLIST.md`. Use interactive web authentication for account
   administration; never persist a package-write token for publication.
6. Confirm repository and CI secrets do not contain `NPM_TOKEN` or another npm
   registry write credential. A broken OIDC relationship must fail closed.

### Confirm done
- [ ] Old token revoked on npmjs.com
- [ ] All unneeded package/org write tokens revoked
- [x] No replacement publish token created
- [x] Local `~/.npmrc` contains no registry auth token (verified 2026-07-10)
- [x] All seven OIDC trusted-publisher mappings read back correctly (verified 2026-07-10)
- [x] No npm write credential is stored in GitHub Actions or Vercel (verified 2026-07-10)
- [ ] Mark this checklist complete in the next commit message

---

## After both rotations

Send a one-line confirmation in our next message:

> "Rotated the DB password; revoked npm write credentials and removed the local
> token fallback."

That's the verification step that closes the audit finding.

---

## Why this isn't automated

Both rotations require either a 2FA prompt (npm) or a logged-in
admin session (Supabase) that I can't drive. They are one-time,
hand-driven, security-sensitive operations. The tradeoff of
automating them via stored API keys would create exactly the
class of secret EMILIA's protocol is designed to gate — that's the
wrong precedent to set.
