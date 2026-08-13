# WAG to AEB token-issuance profile v1

Status: experimental EMILIA interoperability profile

Source: `draft-carleton-workload-authz-grant-00`

Source lock: `standards/observatory/wag-00-source-lock.v1.json`

## Purpose

This profile lets an authorization server evaluate a Workload Authorization
Grant (WAG) as one native evidence leg and bind the observed RFC 7523 token
request to one exact EMILIA CAID.

It does not modify WAG. It does not turn WAG properties into authorization.
It does not treat WAG as evidence that a human approved anything. It does not
use a WAG grant to authorize a downstream tool or resource-server action.

## Relying-party pins

The relying party pins all of the following outside presenter control:

- WAG revision and reviewed source bytes;
- one per-tenancy issuer and tenancy identifier;
- accepted ES256 verification keys, each under an exact `kid`;
- permitted WIMSE authority component, when URI-form identifiers are required;
- authorization-server issuer and token endpoint;
- RFC 8707 target resource;
- signed property claims that are material to the local decision;
- grant lifetime, status freshness, and WIMSE identifier requirements; and
- the AEB mapping profile and adapter implementation.

Discovery can refresh candidate metadata. It never changes these pins inside
an evaluation. An issuer or key change is a relying-party configuration event.
The `property_claims` pin MUST name every WAG claim that can affect the local
token-issuance decision. A deployment that lets an unlisted claim affect that
decision is outside this profile because the CAID would omit material policy
input.

## Native verification

The adapter verifies the compact JWT signature, `iss`, `sub`, `aud`, `jti`,
`iat`, `exp`, per-tenancy key selection, material properties, current status,
and the observed `grant_type` and `resource` parameters. A previously unseen
signed `sub` is accepted under the pinned per-tenancy issuer, as WAG requires;
it does not require per-agent registration. The stable replay unit
is derived from `(draft revision, iss, sub, jti)`.

The WAG signature covers the JWT claims. It does not cover the RFC 8707
`resource` parameter carried beside the assertion. This profile binds the
resource observed by the authorization server into the token-issuance CAID;
it does not claim that the WAG issuer signed that parameter.

## Exact action projection

The only action type defined by this profile is:

`oauth.access-token.issue.1`

Its material fields are:

- authorization-server issuer and token endpoint;
- WAG issuer, subject, `jti`, and assertion digest;
- target resource; and
- the relying-party-selected signed property claims.

Changing any material field changes the CAID or causes native verification to
refuse. WAG alone cannot map a downstream action. That request returns
`INDETERMINATE` with `wag:does_not_bind_downstream_action`.

## Consumption and local policy

WAG -00 requires a unique `jti` but does not define a replay-consumption
mechanism. This EMILIA profile adds one-time AEB consumption at token issuance.
That is an EMILIA composition rule, not a WAG -00 conformance claim.

After native verification and exact-action mapping, the authorization server
still makes its own local authorization decision. Signed Agent Properties are
inputs to that policy. Possessing a Property is not authorization.

## Reproduction

From the repository root:

```sh
npm run conformance:composition:wag
```

The command runs the adapter tests and the hostile vector catalog, then emits a
JSON report plus a paste-ready Implementation Status paragraph. An external
run reproduces the EMILIA reference implementation. It is not an independent
implementation, IETF adoption, certification, or endorsement.
