# Experimental WIMSE/OAuth Principal-Separation AEB Profile v2

Status: experimental application profile. This is not a WIMSE, OAuth, CAID,
or AEB core-protocol revision.

Implementation:
`@emilia-protocol/verify/aeb-wimse-oauth-principal-adapter`

Base verifier and mapper:
`@emilia-protocol/verify/aeb-wimse-oauth-adapter` version 1

Vectors:
`conformance/vectors/wimse-oauth-principal-aeb.v2.json`

## 1. Purpose

The v1 WIMSE/OAuth/SPT adapter verifies the native cryptography and material
action, but it intentionally emits one workload subject. A deployment can
therefore blur several actors that have different security meanings:

1. the logical agent;
2. the live workload instance holding the current key;
3. the OAuth client;
4. the principal whose authority was delegated;
5. the executor or resource server; and
6. the invoked tool and exact material action.

Version 2 keeps those identities separate and pins their relationships at the
relying party. It wraps the frozen v1 verifier rather than replacing its WIT,
WPT, HTTP Message Signature, OAuth Txn-Token, SPT, freshness, replay, or CAID
checks.

When local policy requires proof that the presentation belongs to the current
TLS connection, the profile can also require the `tls-exporter` channel-binding
type defined by [RFC 9266][rfc9266]. Channel binding remains separate from
workload
identity and action authority. It proves neither who the workload is nor what
the workload may do.

The delegating principal is not automatically the system owner, terminal
accountable authority, or per-action human approver. A deployment that requires
one of those roles carries it as a separate evidence leg and proves the
relationship explicitly. This profile does not overload the workload
credential with an undifferentiated `owner` claim.

## 2. Carried relationship claim

The application profile uses this collision-resistant private JWT claim in the
OAuth Txn-Token:

`https://emiliaprotocol.ai/claims/wimse-principal-binding-v2`

Its value is a closed object:

```json
{
  "@version": "EP-WIMSE-OAUTH-PRINCIPAL-BINDING-v2",
  "logical_agent_id": "wimse://payments.example/agents/release-agent",
  "workload_instance_id": "wimse://payments.example/workloads/release-agent",
  "wimse_subject_semantics": "workload-instance",
  "workload_confirmation_jkt": "<RFC 7638 SHA-256 JWK thumbprint>",
  "oauth_client_id": "client:release-agent-runtime",
  "oauth_grant_type": "urn:example:grant:delegated-payment",
  "oauth_sub_semantics": "delegating-principal",
  "delegating_principal": {
    "id": "principal:customer-42",
    "kind": "human"
  },
  "executor_id": "executor:payments-commit",
  "tool_id": "payment.release"
}
```

This is an application-profile claim, not a claim that the locked WIMSE or
OAuth drafts define it. A transaction-token issuer signature proves what that
issuer asserted. It does not prove the real-world identity, authority, or
humanity of a named party. Deployments requiring independent identity or human
approval must compose separately verified AEB legs.

## 3. Required joins

The relying party pins the complete expected relationship object and the v1
configuration together. The verifier then requires:

- the WIT `sub` to name exactly the logical agent or live workload instance,
  according to the explicit `wimse_subject_semantics` value;
- the WIT `cnf.jwk` RFC 7638 thumbprint to equal the live instance's pinned
  `workload_confirmation_jkt`;
- the OAuth `req_wl` to equal the live workload instance;
- the transaction-token issuer's signed OAuth client and grant-type assertions
  to equal their relying-party pins;
- OAuth `sub` to equal the identity selected by `oauth_sub_semantics`;
- the signed executor identity to match the executor pinned with the native
  OAuth and WIMSE audiences; and
- the signed tool identity to equal the independently verified SPT intent
  tool used by the material action.

OAuth `sub` is never assumed to be a person. Allowed semantics are
`delegating-principal`, `oauth-client`, or `workload-instance`; each has an
explicit equality rule. Even when the signed `delegating_principal.kind` is
`human`, this adapter still returns only the `delegated-workload` AEB role and
a workload subject. A named-human authorization requires its own evidence leg.

## 4. Failure behavior

The profile preserves the AEB decision layers:

- native signatures and request bindings can be `VERIFIED` while relationship
  acceptance remains unresolved;
- an absent or malformed required relationship is `INDETERMINATE`;
- a well-formed signed relationship that conflicts with a relying-party pin is
  `REJECTED`;
- mapping is attempted only after `VERIFIED` and `ACCEPTED`; and
- authorization remains a later, local resource-server decision.

The verifier does not guess a missing client, grant meaning, key relationship,
executor, or tool.

## 5. Discovery is not trust

Discovery of an authorization server, metadata document, JWKS endpoint, or
supported grant does not establish that the relying party accepts that server,
its keys, or its claim semantics. Discovery locates material. Acceptance comes
only from the relying party's configured trust roots and the exact semantic
pins in this profile.

A newly encountered authorization server therefore remains unaccepted until a
separate trust-introduction process authorizes its issuer, keys, audiences,
grant semantics, and any relevant identity relationships. A cryptographically
valid token from a merely discovered server cannot satisfy this profile by
itself.

## 6. CAID boundary

CAID continues to identify the material action. The principal-binding claim is
top-level transaction-token evidence metadata and is not copied into the v1
action projection. The CAID material remains:

- the signed HTTP method, request target, content digest, and WIMSE audience;
- OAuth scope and immutable transaction context; and
- the optional SPT intent.

AEB joins that action to separately verified identity, delegation, and approval
legs. Changing an identity must change profile acceptance, not silently change
the meaning of the material action identifier.

## 7. Hostile cases

The executable test and checked-in vector cover:

- same logical agent, different live workload instance;
- same OAuth `sub`, different OAuth client;
- changed grant type or changed `sub` semantics;
- confirmation-key rotation without an updated relying-party pin;
- tool substitution;
- resource-server or executor substitution; and
- missing relationship evidence returning `INDETERMINATE`;
- a presentation from TLS channel A replayed on TLS channel B;
- a presenter-supplied exporter value when the relying party cannot obtain the
  current connection's exporter independently; and
- an exporter field omitted from the verified WIMSE HTTP Message Signature.

## 8. Optional TLS exporter binding

The relying party pins one of two modes in `tls_exporter_binding`:

- `not-required`; or
- `required-single-authentication-instance`.

The second mode uses the 32-byte `tls-exporter` Exported Keying Material defined
by [RFC 9266][rfc9266] for TLS 1.3. The presenter encodes the value as canonical
unpadded
base64url in the `wimse-tls-exporter` request field and includes that field in
the verified WIMSE HTTP Message Signature. The relying party obtains the value
for the current TLS connection from its own TLS terminator and supplies it to
the adapter separately from the artifact. Equality is checked in constant
time.

A value copied from the presentation is not an independent current-channel
observation. If the profile requires binding and the relying party cannot
obtain the current value, acceptance is `INDETERMINATE`. A covered value from a
different TLS connection is `REJECTED`. An uncovered field is also `REJECTED`.

RFC 9266 provides connection uniqueness, not uniqueness for multiple
upper-layer authentication instances on one TLS connection. This experimental
mode therefore applies only when the integration runs one authentication
mechanism instance on the connection and closes the TLS connection when that
instance concludes, as RFC 9266 requires. Persistent-connection or multiplexed
deployments need a separately reviewed stronger construction. This profile
does not invent one or treat the RFC 9266 channel-binding data as a secret key.

The adapter compares channel-binding inputs. It does not implement TLS, derive
the exporter, verify that a reverse proxy forwarded the correct connection
value, or turn channel binding into identity, delegation, human approval, or
authorization.

The profile is experimental and same-team tested. It is not an independent
implementation or an interoperability claim.

[rfc9266]: https://www.rfc-editor.org/rfc/rfc9266.html
