# Mobile Release Runbook

The repository contains the production backend, permanent package identities,
native reference apps, release checks, and signed-artifact workflow. It does not
contain third-party account credentials and it never uploads an app to a store
without the owner's separate action.

## Permanent identities

| Surface | Value |
|---|---|
| iOS bundle ID | `ai.emiliaprotocol.approver` |
| Apple Team ID | `5M2Z48UQQY` |
| Android application ID | `ai.emiliaprotocol.approver` |
| WebAuthn RP ID | `www.emiliaprotocol.ai` |
| Native API | `https://www.emiliaprotocol.ai/api/` |

Treat each package name, signing certificate, associated-domain statement,
WebAuthn origin, server allowlist, and attestation policy as one trust bundle.
Changing one without the others intentionally causes refusal.

## One-time account work

### Backend

1. Run `supabase migration list` and require exact local/remote history parity
   before any write. Reconcile missing migrations from their reviewed source
   artifacts; do not create empty placeholders or repair the remote ledger just
   to make a push pass. Then run `supabase db push --dry-run` and confirm the
   mobile migration is the only pending production change.
2. Apply `supabase/migrations/20260715180000_mobile_production_platform.sql` to
   the production project through the normal reviewed migration path.
3. Configure the production environment values documented in `.env.example`,
   including both store signing pins, Apple environment, Play cloud project,
   API-key material, and production rate-limit storage.
4. Deploy the web app so the AASA and Digital Asset Links documents are served
   directly from `www.emiliaprotocol.ai` over HTTPS without a redirect.
5. Exercise pairing, enrollment, challenge issuance, terminal commit, concurrent
   replay, database outage, platform-verifier outage, action/evidence transaction
   rollback, lost commit response recovery, and atomic disconnect
   against the production-shaped staging database.

### Apple

1. Register App ID `ai.emiliaprotocol.approver` under team `5M2Z48UQQY`.
2. Enable App Attest and Associated Domains, then create development and App
   Store distribution profiles containing both entitlements.
3. Create the App Store Connect record, privacy answers, age rating, export
   compliance answer, support/privacy URLs, app icon, screenshots, and review
   notes. The review notes must explain that a pairing code from an organization
   is required and provide a working review account or demo path.
4. Place the distribution certificate/profile values in the protected GitHub
   environment `mobile-store-release-approval` using the secret names in
   `.github/workflows/mobile-signed-release.yml`.

### Google Play

1. Create the Play app with package `ai.emiliaprotocol.approver`, enable Play
   App Signing, and record the final app-signing SHA-256 certificate digest.
2. Link the Play Integrity cloud project and enable the optional verdicts used
   by the server profile: app access risk, Play Protect, and device attributes.
3. Put the cloud project number, signing keystore values, and final signing
   digest in the protected release environment and production server config.
   The workflow expects `EMILIA_ANDROID_CERTIFICATE_SHA256_HEX` to be the
   lowercase or uppercase hexadecimal digest printed by `apksigner`; the API
   uses the corresponding base64url digest in
   `MOBILE_ANDROID_CERTIFICATE_DIGESTS`.
4. Complete Data safety, app access instructions, content rating, target
   audience, privacy URL, screenshots, icon, and closed-testing requirements.

## Build gates

Run locally before every release candidate:

```sh
npm run mobile:release-check
npm run mobile:conformance
source .env.production && npm run mobile:production-readiness
MOBILE_TEST_DATABASE_URL='postgresql://...' npm run mobile:db-contract
node --test packages/mobile/*.test.js
npx vitest run \
  tests/mobile-production-attestation.test.js \
  tests/mobile-production-routes.test.js \
  tests/mobile-production-runtime.test.js \
  tests/mobile-production-store.test.js

swift test --package-path sdks/swift-mobile
xcodebuild \
  -project examples/mobile-government/ios/EmiliaGovernmentApproval.xcodeproj \
  -scheme GovernmentApproval -configuration Release \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build

(cd sdks/kotlin-mobile && ./gradlew test :sample:assembleDebug :sample:lintDebug)
```

The `Mobile Apps` workflow repeats those portable checks. The manual `Mobile
Signed Release` workflow then waits on the protected environment, constructs
signed archives, verifies signatures and exact entitlements, scans archives for
obvious secret-file leakage, emits SHA-256 manifests and GitHub build
attestations, and retains artifacts for 14 days. It deliberately does not call
App Store Connect or Google Play upload APIs.

The signed workflow first runs `mobile:production-readiness`. That probe checks
the real Supabase tables and fail-closed RPCs, the production App Attest mode,
the Play package/certificate pins and service account, and both live
`.well-known` association documents. A locally valid app cannot become a signed
release while its deployed backend is stale or only partially configured.

The protected action transition and its portable evidence record are one
PostgreSQL transaction. A candidate must refuse if the evidence head changed,
the record is malformed, the action was already decided, or the write outcome
cannot be recovered by the stable record ID.

The production service role has read-only access to mobile tables. Pairing,
session touch/revocation, challenge state, enrollment, counters, demo seeding,
and terminal decisions mutate only through public-revoked security-definer
functions. `node scripts/check-write-discipline.js` and the disposable database
contract enforce both the JavaScript guard and PostgreSQL privilege boundary.

Required protected secrets are:

- Android: `EMILIA_ANDROID_KEYSTORE_BASE64`,
  `EMILIA_ANDROID_KEYSTORE_PASSWORD`, `EMILIA_ANDROID_KEY_ALIAS`,
  `EMILIA_ANDROID_KEY_PASSWORD`, `EMILIA_ANDROID_CERTIFICATE_SHA256_HEX`, and
  `EMILIA_PLAY_CLOUD_PROJECT_NUMBER`, plus
  `MOBILE_ANDROID_APK_KEY_HASHES`, `MOBILE_ANDROID_CERTIFICATE_DIGESTS`,
  `MOBILE_ANDROID_ASSETLINKS_CERT_SHA256`, and
  `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON`.
- Apple: `EMILIA_IOS_CERTIFICATE_P12_BASE64`,
  `EMILIA_IOS_CERTIFICATE_PASSWORD`, `EMILIA_IOS_PROVISIONING_PROFILE_BASE64`,
  `EMILIA_IOS_CI_KEYCHAIN_PASSWORD`, and `EMILIA_IOS_SIGNING_IDENTITY`.
- Backend: `NEXT_PUBLIC_SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.

The requested semantic version and numeric build number are injected into both
store artifacts and checked after signing. The Android job also checks the exact
package, signing-certificate digest, minimum SDK, target SDK, and non-debuggable
state. The iOS job checks the exact application identifier, production App
Attest environment, associated domain, version, build, and absence of
`get-task-allow`.

The server-side mobile verifier is a separate npm artifact named
`@emilia-protocol/mobile`. Its owner-gated workflow accepts only a matching
`mobile-v<version>` tag and exact `PUBLISH @emilia-protocol/mobile@<version>`
confirmation, runs the package and repository evidence suites, proves the
tarball is reproducible, publishes through npm OIDC with provenance, and then
downloads the registry copy and compares its bytes. Publishing that SDK does
not publish either native app.

## Physical-device hostile release test

For each signed candidate, use at least two enrolled physical devices and one
unenrolled device. Confirm refusal for a mutated action, swapped app identity,
wrong approver, stale challenge, second presentation, concurrent presentation,
revoked session, revoked device credential, App Attest counter rollback, wrong
Play signing certificate, unlicensed Android install, failed integrity service,
captured Android screen, recorded or mirrored iOS screen, offline attestation,
database outage, and executor call without a consumed ceremony.

Export the accepted and refused evidence, verify it with the shipped verifier
from a separate machine, and retain the command output with the signed artifact
hash. A green unsigned simulator build is not a signed-release security result.

## Publication boundary

Signed artifacts may go to TestFlight and a Play internal-testing track only
after the hostile run is attached to the release. Public store publication is a
separate owner decision after privacy, accessibility, support, incident-response,
and pilot acceptance sign-off. The July standards work does not require public
store availability.
