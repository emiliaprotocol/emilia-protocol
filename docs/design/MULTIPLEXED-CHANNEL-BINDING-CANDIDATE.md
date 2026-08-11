# Multiplexed channel-binding candidate (NOT IMPLEMENTED)

Status: candidate construction awaiting external cryptographic review. Nothing
in this note is implemented, normative, or part of any conformance claim. The
shipped profile (wimse-oauth-principal-aeb-profile-v2) deliberately restricts
RFC 9266 binding to one authentication instance per TLS connection and states
that multiplexed deployments need a separately reviewed stronger construction.
This note records the construction we intend to put forward for attack, so the
review request is concrete rather than rhetorical. Do not implement before
that review or an equivalent TLS/SEAT review.

## Construction

    K_bind = TLS-Exporter("EXPORTER-EMILIA-AUTH-BINDING-v1",
                          empty_context, 32)

    M = frame(version,
              presenter_role,
              authentication_instance_nonce,
              relying_party_audience,
              exact_action_caid,
              evidence_digest)

    tag = HMAC-SHA-256(K_bind, M)

- `frame()` is a length-prefixed field encoding: each field is emitted as an
  unsigned 32-bit big-endian byte length followed by the field bytes, in the
  fixed order above. No maps, no floats, no key ordering, no optional
  normalization, no payload-selected algorithms.
- `tag` is carried in a request field covered by the workload's asymmetric
  HTTP Message Signature.
- The relying party derives `K_bind` independently from its own TLS stack and
  compares in constant time.
- `authentication_instance_nonce` is a relying-party challenge consumed
  exactly once. Because it only disambiguates authentication instances on one
  connection, its consume-once state is connection-local and dies with the
  connection: no durable store and no cross-domain coordination.
- `presenter_role` prevents reflection of a tag between the two ends of one
  connection. `relying_party_audience` covers connection coalescing and
  virtual hosts. `exact_action_caid` and `evidence_digest` prevent action and
  presentation substitution under a valid channel.

## Invariants

1. The secret exporter output `K_bind` is never transmitted, logged, or
   included in evidence.
2. The public RFC 9266 channel-binding value (`EXPORTER-Channel-Binding`) is
   never used as an HMAC key. It is channel-binding data, designed to be
   exposed and compared; the secret key comes only from the separate
   `EXPORTER-EMILIA-AUTH-BINDING-v1` invocation.
3. If the verifier cannot obtain exporter output for the current connection,
   the result is INDETERMINATE, never a pass.
4. TLS 1.3 KeyUpdate does not rotate the exporter master secret and
   resumption produces a fresh one per connection, so `K_bind` is stable
   within a connection and unique across connections. No epoch handling is
   required or defined.

## Open design question (to pose, not pre-answer)

The instance nonce could instead live in the exporter context, yielding a
per-instance `K_bind` with no message-side nonce. The two shapes are close to
equivalent because the exporter interface is already a PRF; the choice is one
we intend to put to external reviewers rather than settle internally.

## Honest deployment limit

Where TLS terminates at a proxy or load balancer, the verifier cannot claim
channel binding unless the terminator exposes the exporter operation over an
authenticated, trusted interface; otherwise the result is INDETERMINATE. In
common cloud deployments INDETERMINATE will therefore be the frequent path.
The construction is strongest where termination is local to the relying
party: mutual-TLS service meshes, sidecar termination, and direct
agent-to-agent connections.

## Registration note

"EXPORTER-EMILIA-AUTH-BINDING-v1" is a distinctive private-use label for the
experimental phase. If the construction survives review and is implemented, an
IANA registration in the TLS Exporter Labels registry is required before any
non-experimental use.
