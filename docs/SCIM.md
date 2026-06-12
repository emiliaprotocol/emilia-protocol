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

## Conformance

The mapping, filter, and PATCH semantics are covered by `tests/scim-core.test.js`
(24 cases) and the full create → list → filter → deprovision → delete lifecycle
plus the auth gate by `tests/scim-routes.test.js` (10 cases). Storage is
`supabase/migrations/095_scim_provisioning.sql`.

> **Live IdP round-trip:** the server is conformance-tested against the SCIM
> protocol directly (our tests act as the IdP client). A live end-to-end run
> against a specific Okta/Entra tenant is part of onboarding — the connector
> settings above are everything that tenant needs.
