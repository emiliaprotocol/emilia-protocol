# Government Mobile Deployment

## Components

1. **System-of-record adapter** resolves an action reference into authoritative
   action and presentation bytes.
2. **Profile service** pins accepted apps, origins, enrollments, and integrity
   requirements.
3. **Ceremony service** registers challenges and verifies mobile responses.
4. **Platform verifier** validates App Attest or Play Integrity evidence.
5. **Consumption store** atomically consumes exact challenge bodies.
6. **Evidence log** records every acceptance and refusal under a strict write
   policy.
7. **Protected executor** requires the consumed ceremony before applying the
   consequential change.
8. **Agency authorization adapter** authenticates the caller through the
   agency's existing SSO, mTLS, or workload-identity system and authorizes the
   exact profile, action reference, approver, app, and enrolled device.
9. **Action continuity store** groups approver assignments into immutable
   CAID-bound revisions, projects aggregate quorum, and records lifecycle
   events and material changes.
10. **Provider-outcome verifier** resolves ambiguous operations only against an
    organization-pinned Ed25519 executor key and exact operation bindings.

## HTTP shape

The Fetch-compatible `createMobileHttpHandler` exposes:

```text
POST /v1/mobile/challenges
POST /v1/mobile/ceremonies
POST /v1/mobile/enrollments/challenges
POST /v1/mobile/enrollments
```

The hosted reference adapter additionally exposes pairing exchange, an
entity-scoped inbox, a demo action injector for authenticated operators, and an
atomic disconnect endpoint under `/api/v1/mobile`. The disconnect endpoint
revokes both the bearer session and its bound enrollment in one database
transaction; deleting local app data alone is not revocation.

The continuity routes have three distinct authority classes:

| Route | Authority | Purpose |
|---|---|---|
| `GET /api/v1/mobile/inbox` | paired mobile session | Active action revisions, identity, quorum, lifecycle, changes, alignments, and events |
| `GET /api/v1/mobile/history` | paired mobile session | Current, superseded, and terminal action history with bounded passports |
| `GET /api/v1/mobile/actions/{actionReference}/passport` | paired mobile session | One bounded decision passport; no raw evidence |
| `POST /api/v1/mobile/actions/{actionReference}/withdraw` | paired mobile session | Withdraw this approver's approval before consumption; body is exactly `{}` |
| `POST /api/v1/mobile/actions/{actionReference}/consume` | write-capable organization key | Atomically consume one authorized active revision and freeze the intended executor/key |
| `POST /api/v1/mobile/actions/{actionReference}/outcomes` | write-capable organization key | Mark timeout indeterminate or reconcile pinned provider evidence |
| `POST /api/v1/mobile/actions/{actionReference}/supersede` | write-capable organization key | Create a new CAID-bound revision and material diff |
| `POST /api/v1/mobile/actions/{actionReference}/alignments` | write-capable organization key | Record a profile-scoped cross-system comparison |
| `POST /api/v1/mobile/executors` | organization admin key | Register or rotate a pinned Ed25519 provider-outcome key |

All hosted responses are tenant-scoped and carry `Cache-Control: no-store`.
The complete request and response schemas are in
[`openapi.yaml`](../../openapi.yaml).

All four endpoints MUST authenticate the caller and pass the resulting principal
to the controller. The controller's mandatory `authorize` hook runs before a
system-of-record lookup or ceremony verification. Authentication failure,
authorization failure, and authorization-backend failure all refuse; there is
no anonymous mode. Deployments SHOULD rate-limit all endpoints by principal,
device enrollment, and network source.

Enrollment uses a separate mandatory `authorizeEnrollment` hook at both
challenge issuance and completion. It MUST bind the authenticated agency
principal to the requested `approver_id`; request-body identity is never
authority. This check runs before passkey or platform-attestation verification.

Challenge request:

```json
{
  "profile_id": "agency.high-assurance.mobile.v1",
  "action_reference": "case-system:approval:9482",
  "approver_id": "ep:approver:case-supervisor",
  "decision": "approved",
  "platform": "ios",
  "app_id": "gov.example.approvals",
  "device_key_id": "ep:key:mobile-enrollment-42"
}
```

The endpoint rejects unknown members, including caller-supplied `action`,
`presentation`, `policy`, `profile`, or trust keys. After selecting an outcome, the app obtains a fresh
challenge and presents the challenge's own `presentation` before the final
passkey prompt.

`presentation` is the closed `EP-MOBILE-PRESENTATION-v1` object. It contains
only `title`, `summary`, `risk`, `consequence`, and flat string-valued
`material_fields`; every field is rendered by both reference apps. Unknown,
nested, unversioned, or oversized values are refused before platform or passkey
signing. This is a faithful review surface contract, not a claim that a
compromised operating system displayed honest pixels or that the user perceived
them.

Challenge issuance now uses `EP-MOBILE-CHALLENGE-v2`. The outer challenge
remains `AE-CHALLENGE-v1`, while its closed signed `authorization_context`
includes:

```json
{
  "ep_version": "1.0",
  "context_type": "ep.signoff.v1",
  "action_reference": "case-system:approval:9482",
  "action_caid": "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:...",
  "action_digest": "sha256:...",
  "mobile_binding": {
    "profile": "EP-MOBILE-CHALLENGE-v2"
  }
}
```

The omitted context members remain mandatory and bind the action hash, display
hash, policy, initiator, approver and quorum position, nonce, decision, validity
window, app, enrolled credential, and attestation key. The WebAuthn challenge
is derived from the complete context. The server recomputes CAID and action
digest from authoritative action bytes; callers cannot nominate them.

Android enrollment also creates a non-exportable P-256 `AndroidKeyStore` key.
Play Integrity covers the canonical enrollment binding containing that public
key, and each ceremony requires a signature from the same key. A synced or
restored passkey without the enrolled device key therefore refuses. iOS retains
the separate active App Attest key uniqueness rule and accepts Apple's standard
Base64 key identifiers without rewriting them.

Ceremony request:

```json
{
  "challenge": {
    "@version": "AE-CHALLENGE-v1",
    "challenge_profile": "EP-MOBILE-CHALLENGE-v2"
  },
  "response": { "@version": "EP-MOBILE-CEREMONY-v1" }
}
```

The HTTP layer MUST use a strict JSON parser that rejects duplicate member
names, non-finite numbers, unsafe integers, and trailing data before calling
the object-level controller. The included handler enforces HTTPS, JSON content
type, a bounded body, duplicate-name and Unicode-scalar checks, exact endpoint
shapes, and agency authentication. Object-level profile and ceremony checks
then reject unsafe numeric values before acceptance.

## Executor contract

The verifier result is not itself permission to mutate the system of record.
The local executor checks that:

- `valid=true`, `verdict=verified`, and `decision=approved`;
- the action hash matches the pending operation;
- local authorization policy still permits execution; and
- the ceremony identifier has not already been used for an effect.

Denials and all `refuse_*` verdicts are evidence events and never authorize an
effect.

## Consequence and reconciliation contract

An aggregate quorum transition to `AUTHORIZED` does not itself mutate the
protected system. The executor first calls the consumption endpoint with a
tenant-scoped `operation_id` and registered `executor_id`; the service
atomically changes the active action group to `CONSUMED`, freezes the executor's
currently active key on the operation, and returns a server-random
`consumption_nonce`.

If the provider returns a conclusive response, the executor reconciles it with
an `EP-MOBILE-PROVIDER-OUTCOME-v1` statement. The statement is signed with
Ed25519 and binds:

- `operation_id`;
- `action_caid` and `action_digest`;
- `consumption_nonce`;
- `executor_id`;
- `outcome` (`executed` or `refused`);
- `observed_at`; and
- `provider_reference`.

The proof public key and derived key ID must match both the key frozen at
consumption and the organization's still-active executor-key pin. The database
rechecks that exact pin in the outcome-commit transaction, preventing key
rotation or revocation from racing reconciliation. Any mismatch refuses. The
complete signed provider statement is retained server-side; mobile history and
passports expose only its digest. If the provider call times out or its effect
is otherwise unknown, record `state=indeterminate` without evidence.
`INDETERMINATE` has `retry_safe=false`: do not call the provider again. Poll or
query the provider through an authenticated channel, then submit its signed
evidence to reconcile the original operation.

Decision passports are summaries for review and export. They contain CAID,
action digest, decision and outcome evidence digests, quorum, lifecycle,
consumption nonce, and a passport digest. They intentionally exclude raw
WebAuthn assertions, platform attestation tokens, provider payloads, and
provider signatures.

## Migration and rollout boundary

The continuity tables and security-definer transitions are introduced by
`supabase/migrations/20260720181619_mobile_action_continuity.sql` and hardened
forward-only by
`supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql`.
Source review,
merging, migration application, deployed API verification, signed native builds,
and app-store distribution are separate gates. Before enabling the continuity
routes in an environment:

1. require local/remote migration history parity;
2. apply the reviewed migration through the normal deployment path;
3. run the disposable database contract and the production-readiness probe;
4. register the intended executor key with an organization-admin credential;
5. verify one authorized consumption, one duplicate-consumption refusal, one
   indeterminate timeout, and one pinned-evidence reconciliation; and
6. confirm the protected executor has no bypass and never blindly retries an
   indeterminate operation.

The repository contains the reference implementation and migration. Their
presence does not prove that a particular environment has applied or deployed
them, and it does not establish native app-store publication.

## Availability

Platform attestation is an online dependency. During an outage, the service
refuses rather than silently dropping to a passkey-only tier. Agencies that
need emergency procedures should define a separate, explicit break-glass
profile with separate credentials, quorum, time bounds, logging, and after-action
review. It must not be an implicit fallback in this profile.
