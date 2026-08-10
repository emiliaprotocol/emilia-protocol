<!-- SPDX-License-Identifier: Apache-2.0 -->
# OAuth/RAR profile for the Authorization Bundle

Status: experimental application profile. This document is not an
Internet-Draft, an OAuth extension, or an authorization decision.

`EP-AUTHORIZATION-BUNDLE-v1` is transport neutral. This profile defines one
closed `authorization_binding` projection for deployments that have already
verified an OAuth transaction challenge, actor context, and Rich Authorization
Request under their native rules.

```json
{
  "profile": "EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1",
  "authorization_server": "https://as.example.com",
  "transaction_id": "97053963-771d-49cc-a4e3-20aad399c312",
  "actor": "spiffe://example.com/agent/6526f880",
  "delegated_subject": "user:alice",
  "authorization_details_digest": "sha256:2a71...",
  "action_mapping_profile": "https://example.com/mappings/payment-v1"
}
```

`delegated_subject` is the only optional member. The remaining members are:

- `authorization_server`: the independently trusted authorization server.
- `transaction_id`: the native transaction identifier joining challenge,
  request, grant, and executor-side admission.
- `actor`: the workload actor derived from natively verified context, never an
  unverified self-description supplied by the agent.
- `delegated_subject`: the native delegated principal, when one exists.
- `authorization_details_digest`: SHA-256 over the JCS serialization of the
  complete granted `authorization_details` array.
- `action_mapping_profile`: the relying-party-pinned, loss-aware mapping from
  the verified RAR details to the Authorization Bundle Action Object and CAID.

The relying party first verifies the native challenge, grant, actor, subject,
and RAR details. It then derives the expected projection above and calls
`matchOAuthRarAuthorizationBinding`. Only `MATCH` is supplied to the neutral
Bundle verifier as `expectedAuthorizationBinding`. An unavailable native
verifier or mapping is `INDETERMINATE`; malformed or unequal bytes are a hard
mismatch.

The profile does not make the Bundle an OAuth grant. The authorization server
still makes the native grant decision, the relying party still makes its local
authorization decision, and the executor still performs durable one-time
admission. A Bundle does not invalidate, consume, or narrow an OAuth token by
itself.
