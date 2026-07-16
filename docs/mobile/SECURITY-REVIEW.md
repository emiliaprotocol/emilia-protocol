# EMILIA Approver Security Review

Review date: 2026-07-15. Scope: the native iOS and Android reference apps,
mobile SDKs, `/api/v1/mobile`, platform-attestation adapters, durable PostgreSQL
state, and signed-release workflow.

This review covers source and unsigned local artifacts. A store-signed build is
not acceptance-cleared until the physical-device campaign in `RELEASE.md` has
run under the final Apple profile and Play signing certificate.

## Closed findings

| Severity | Finding | Closure |
|---|---|---|
| Critical | A terminal action update and its portable evidence append were separate writes. A crash after `approved` but before audit could leave an actionable state without admissible evidence. | `commit_mobile_action_decision` now validates and appends the canonical hash-chain record in the same PostgreSQL transaction that consumes the challenge and updates the protected action. Malformed evidence rolls the action back; response-loss recovery reads the exact stable record ID. |
| High | Paired challenge, enrollment, and platform-attestation routes had no durable per-session throttle. | Added fail-closed IP and session categories backed by the existing durable rate limiter. The protected handler is not entered after an exhausted network limit. |
| High | iOS followed redirects and buffered an unbounded response while carrying a bearer token. Production API identity was configurable at runtime. | Production host/path are pinned, redirects are refused, MIME must be JSON, and responses are capped at 1 MiB. Android enforces the same production endpoint and release builds cannot override it. Signed-artifact CI inspects both. |
| High | The production adapter returned the generic logger's shape in tests but a different database shape at runtime. | PostgreSQL now stores and returns the verifier-native `{seq, prev_hash, record_id, ..., hash}` record, and every readback is rehashed and matched to the expected event. |
| High | App Attest and WebAuthn monotonic counters shared a key namespace. | Counter domains are separated as `mobile:platform-attestation` and `mobile:webauthn`. |
| High | A read-only organization credential could create pairing state in an early route shape. | Pairing and demo injection require an authenticated, write-capable organization principal before any protected write. |
| High | Five mobile mutations bypassed the repository's trust-table write guard through direct service-role table access. A future route bug could therefore have changed pairing, session, challenge, or action state outside the reviewed transition functions. | Every mobile table is now in `TRUST_TABLES`; all routes use the guarded client; remaining mutations use validated, public-revoked security-definer RPCs; and the service role has select-only table privileges. Token authentication also refuses if the atomic session touch loses a revocation/expiry race. |
| High | A challenge issued before session revocation could still reach the terminal action transaction after that session was revoked. | Each action challenge now carries its exact session ID. The terminal transaction locks and rechecks that session, binds the portable evidence record to it, and serializes revocation against approval so only the transaction that wins the session lock can take effect. |
| High | A production Android deployment could silently inherit a debug app identity or operate without certificate/Google verifier pins. | Production has no debug fallback. The runtime, readiness probe, release workflow, and Digital Asset Links route all fail closed until the Play app, package key, certificate, service account, and version policy are pinned. |
| Medium | Personalized mobile responses and refusal details did not all carry an explicit private cache policy. | Every mobile success and problem response now sets `no-store`, `no-cache`, `nosniff`, and `no-referrer`. |
| Medium | iOS could expose exact-action content in the app-switcher snapshot or while capture was detected. | Inactive and captured states render a neutral privacy shield; capture also clears the pending ceremony and blocks signing/submission. Android uses `FLAG_SECURE`. |
| Medium | A production demo injector could have become an accidental action-authoring API. | It is disabled unless `MOBILE_DEMO_ENABLED=true`, requires a write principal, accepts only a named built-in scenario, and never accepts caller-supplied action bytes. The local visual showroom is compiled only in Debug and is visibly marked `DEMO`. |

## Executed attack classes

- Action, display, profile, origin, app, credential, device, approver, nonce,
  expiry, decision, and attestation substitution.
- Replayed, concurrently presented, stale, unregistered, already-decided, and
  counter-rollback ceremonies.
- Unknown JSON members, duplicate keys, non-safe numbers, invalid UTF-8,
  oversized request/response bodies, malformed CBOR, and trailing CBOR bytes.
- Pairing reuse, app-identity substitution, read-only API-key use, session
  revocation races, and disabled-demo bypass attempts.
- Database head contention, stale expected heads, malformed canonical records,
  response loss after commit, direct table mutation, session touch/revocation
  races, store outage, audit outage, and verifier outage.
- Debug signing, wrong package/bundle identity, wrong certificate, development
  App Attest entitlement, `get-task-allow`, secret-file leakage, and release
  version drift in the signed-artifact workflow.

## Static-tool adjudication

- `gitleaks` found no secret in the mobile source/release surface.
- `npm audit` reported zero known dependency vulnerabilities at review time.
- Android lint reports zero findings; Swift Release build and Xcode static
  analysis succeed.
- Semgrep reported three review items. The Keychain token is intentionally
  device-only and available while unlocked because inbox polling cannot require
  a biometric read; a fresh passkey still gates every decision. The exported
  Android activity is the launcher/deep-link entry and only imports a pairing
  code. AES-GCM uses a fresh provider-generated IV and a Keystore key requiring
  randomized encryption. None of the three establishes an authorization path.

## Residual assumptions

- Apple and Google platform verdicts are online relying-party inputs. The
  portable execution record truthfully states that they were checked; it does
  not make those vendor verdicts independently reproducible offline.
- App Attest, Play Integrity, passkeys, and screen-capture defenses do not prove
  human perception or honest pixels on a fully compromised operating system.
- The service role, production signing accounts, protected release environment,
  WebPKI endpoint, Apple/Google roots, and durable rate-limit/store providers
  remain operational trust anchors.
- The system proves what passed through this executor gate. It cannot prove an
  organization has no uninstrumented path around the gate.

## Remaining acceptance gates

1. Reconcile the production migration ledger with reviewed source artifacts,
   apply the mobile migration through the normal migration path, and pass
   `npm run mobile:production-readiness` against the live deployment.
2. Register the Apple App ID/profile and Play app/signing identity, then run the
   protected signed-release workflow.
3. Execute the physical-device hostile and accessibility matrix from
   `RELEASE.md`; retain its output beside the signed artifact hashes.
4. Publish to TestFlight and Play internal testing first. Public store release
   remains an owner decision after pilot, privacy, accessibility, support, and
   incident-response acceptance.
