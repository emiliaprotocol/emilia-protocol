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

Ceremony request:

```json
{
  "challenge": { "@version": "AE-CHALLENGE-v1" },
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

## Availability

Platform attestation is an online dependency. During an outage, the service
refuses rather than silently dropping to a passkey-only tier. Agencies that
need emergency procedures should define a separate, explicit break-glass
profile with separate credentials, quorum, time bounds, logging, and after-action
review. It must not be an implicit fallback in this profile.
