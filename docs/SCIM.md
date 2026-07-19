# SCIM 2.0 Provisioning

EP exposes a standards-compliant **SCIM 2.0** (RFC 7643 / RFC 7644) endpoint so
enterprise and government customers provision and **deprovision** the named
humans who can sign off — directly from their identity provider (Okta, Azure AD /
Entra ID, Ping, OneLogin), no manual user management.

This is the directory side of the "named human" guarantee: when an approver is
offboarded in your IdP, they are deprovisioned in EP in the same sync, so the set
of humans who *could* sign is always exactly your live directory.

## Base URL

```
https://www.emiliaprotocol.ai/api/scim/v2
```

`GET /ServiceProviderConfig` advertises capabilities; `GET /ResourceTypes` and
`GET /Schemas` describe the resources.

## 1. Mint a provisioning token

Authenticate with your EP API key and mint a SCIM bearer token (shown once):

```bash
curl -s https://www.emiliaprotocol.ai/api/scim/v2/provisioning-token \
  -H "authorization: Bearer ep_live_..." \
  -H "content-type: application/json" \
  -d '{"label":"Okta production"}'
```

The response includes the `token` (prefix `ep_scim_`) and your `scim_base_url`.
The token is scoped to your tenant; one tenant never sees another's directory.

## 2. Configure your IdP

| Field | Value |
|---|---|
| SCIM connector base URL | `https://www.emiliaprotocol.ai/api/scim/v2` |
| Authentication mode | OAuth Bearer Token (HTTP header) |
| Bearer token | the `ep_scim_...` token from step 1 |
| Provisioning actions | Create, Update, Deactivate (and Push Groups) |

## Supported operations

| Resource | Operations |
|---|---|
| Users | `GET` (list + `filter=userName eq "…"` / `externalId eq "…"`), `POST`, `GET/PUT/PATCH/DELETE /Users/{id}` |
| Groups | `GET`, `POST`, `GET/PUT/PATCH/DELETE /Groups/{id}` |

- **Deprovision** is `PATCH … {"op":"replace","path":"active","value":false}` —
  both the path form and the no-path `{value:{active:false}}` form Azure sends
  are handled.
- **Group membership** sync supports `add` (append), `replace` (overwrite), and
  `remove` (`members[value eq "…"]`).
- **ETags** are returned (`meta.version`) and the service advertises
  `etag.supported = true`.

## Signing-authority linkage

The point of SCIM here is signing authority that tracks your directory. The link
is the identity itself: a user's `userName` IS the `approver_id` the WebAuthn
enrollment flow uses.

- **Provision (active):** the human becomes eligible to enroll a signing passkey
  at `/api/v1/approvers/webauthn/register-options` (recorded in the audit trail).
  No key is minted on their behalf — that would be operator custody (Class C).
- **Directory anchor:** once your org provisions a directory, enrollment is
  gated on it. An operator holding `approver.enroll` can only bind an
  `approver_id` that matches an **active** provisioned `userName` (normalized
  identically to the SSO directory check), so an operator can no longer name an
  approver the directory does not carry. Each credential records its
  `enrollment_basis`: `directory` when it matched a provisioned user, or
  `operator_attested` when the org has no directory (the pilot path). The org →
  directory link is the SCIM provisioning token, which is the only record
  carrying both your `organization_id` and your directory `tenant_id`; because
  one org can mint several tokens, the lookup resolves the full set of your
  directory tenants and an active match in any of them anchors the enrollment.
- **The anchor is sticky.** Minting a SCIM token commits your org to
  directory-anchored enrollment: from then on, an approver must be synced (and
  active) before it can enroll. **Revoking the token does not disarm the
  anchor** — the directory link is keyed on the existence of a token row, not on
  its liveness, so you cannot drop back to operator-attested enrollment by
  revoking a bearer token. Exiting directory governance requires an
  administrator to hard-delete the token rows. This is deliberate: token
  revocation is reachable by the same privileged operator the anchor defends
  against, so it must not be a one-step bypass. A directory-mode credential is
  stored under the **normalized** `userName`, which is the same value the
  deprovision path revokes by — so an IdP offboarding reliably revokes it.
- **Deprovision (`active=false` or `DELETE`):** every live approver credential
  for that `userName` is revoked **in the same write**. Offboarding in your IdP
  removes signing authority in the same sync. Re-activation makes the human
  eligible to *re-enroll*; it never resurrects a revoked key.

## Conformance

The mapping, filter, and PATCH semantics are covered by `tests/scim-core.test.js`
(24 cases) and the full create → list → filter → deprovision → delete lifecycle,
the auth gate, and the approver-linkage (provision-eligible / deprovision-revokes /
re-activation-never-resurrects) by `tests/scim-routes.test.js` (15 cases). Storage
is `supabase/migrations/095_scim_provisioning.sql`.

> **Live IdP round-trip:** the server is conformance-tested against the SCIM
> protocol directly (our tests act as the IdP client). A live end-to-end run
> against a specific Okta/Entra tenant is part of onboarding — the connector
> settings above are everything that tenant needs.
