# Enterprise SSO (SAML 2.0 + OIDC)

EP supports enterprise Single Sign-On so the humans who configure policy and own
signoff authenticate through your identity provider — SAML 2.0 (Okta, Entra ID,
Ping, ADFS) or OIDC (Okta, Entra, Google, Auth0, Keycloak). SSO pairs with
[SCIM provisioning](./SCIM.md): SSO authenticates the human; SCIM keeps the set
of valid humans in sync with your directory.

All signature verification uses vetted libraries — `@node-saml/node-saml`
(`xml-crypto`) for SAML XML-DSig, `jose` for OIDC JWKS/JWT — never hand-rolled
crypto.

## Configure (per tenant, with your EP API key)

```bash
# SAML
curl -s https://www.emiliaprotocol.ai/api/sso/connections \
  -H "authorization: Bearer ep_live_..." -H "content-type: application/json" \
  -d '{"protocol":"saml","saml_idp_entry_point":"https://YOUR_OKTA_DOMAIN/app/.../sso/saml","saml_idp_cert":"MIID...="}'

# OIDC
curl -s https://www.emiliaprotocol.ai/api/sso/connections \
  -H "authorization: Bearer ep_live_..." -H "content-type: application/json" \
  -d '{"protocol":"oidc","oidc_issuer":"https://YOUR_OKTA_DOMAIN","oidc_client_id":"0oa...","oidc_client_secret":"..."}'
```

## SAML 2.0 (EP is the Service Provider)

| Endpoint | Purpose |
|---|---|
| `GET /api/sso/saml/metadata` | SP metadata XML for your IdP admin (entityID, ACS, POST binding) |
| `GET /api/sso/saml/login?tenant=<id>` | SP-initiated login → AuthnRequest redirect (tenant carried in RelayState) |
| `POST /api/sso/saml/acs` | Assertion Consumer Service — validates the signed Response |

The ACS enforces `wantAssertionsSigned`: an unsigned assertion, a wrong-key
signature, a stale `Conditions` window, or a wrong audience is **rejected** (401).
On success it resolves the asserted `NameID`/email against the SCIM directory and
reports whether it is a known, active approver.

## OIDC (EP is the Relying Party)

| Endpoint | Purpose |
|---|---|
| `GET /api/sso/oidc/login?tenant=<id>` | Authorization Code + PKCE; state/nonce/verifier in a signed httpOnly cookie |
| `GET /api/sso/oidc/callback` | Exchanges the code, validates the ID token against the provider JWKS |

The callback verifies the signed state cookie matches the returned `state` (CSRF),
exchanges the code (PKCE), and validates the ID token's signature, `iss`, `aud`,
`exp`, and `nonce`. A token signed by a key not in the provider's JWKS — or any
mismatch — is **rejected** (401).

## Session + secret handling

- **Session.** A successful SAML ACS or OIDC callback mints a signed EP session
  (HS256 JWT, `ep_session` httpOnly cookie, 8h). `GET /api/sso/session` returns
  the verified identity + the SCIM-directory verdict; `DELETE /api/sso/session`
  logs out. The session asserts *who authenticated*; Class-A signoff still
  requires the approver's passkey ceremony per action.
- **Client secret at rest.** A tenant's `oidc_client_secret` is sealed with
  AES-256-GCM (`lib/crypto/secret-box`) before storage and decrypted only at
  token-exchange time. The stored format is versioned (`epenc:v1:`) so moving
  the key into a dedicated KMS is a rolling re-encryption, not a migration.

## Conformance

The security-critical validation is unit-tested against fixture IdPs (no live
provider needed):

- `tests/sso-oidc.test.ts` (12) — signs real ID tokens with a fixture key and
  proves accept-valid / reject wrong-aud / wrong-iss / expired / bad-nonce /
  key-not-in-JWKS, plus PKCE (RFC 7636 vector), discovery, token exchange.
- `tests/sso-saml.test.ts` (8) — SP metadata + AuthnRequest structure, rejects
  unsigned/garbage, and (where openssl is present) signs a real SAML assertion
  and proves the ACS accepts it and rejects a different-key signature.
- `tests/sso-state.test.ts` (5) — the HMAC state token: tamper + expiry + wrong-secret rejection.
- `tests/sso-session.test.ts` (6) — EP session mint/verify, tamper + wrong-secret + cookie parsing.
- `tests/secret-box.test.ts` (7) — AES-256-GCM round-trip, tamper rejection, plaintext-passthrough rollout.

> **Live IdP round-trip:** the validators are exercised against fixture
> providers here; connecting a specific Okta/Entra tenant (its real signing
> cert / client credentials) is part of onboarding. The connector settings above
> are everything that tenant needs.
