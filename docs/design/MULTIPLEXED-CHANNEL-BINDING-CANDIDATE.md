# Multiplexed channel-binding candidate (NOT IMPLEMENTED)

Status: candidate construction awaiting external cryptographic review. Nothing
here is implemented, normative, or part of any conformance claim. The shipped
profile (wimse-oauth-principal-aeb-profile-v2) restricts RFC 9266 binding to
one authentication instance per TLS connection and states that multiplexed
deployments need a separately reviewed stronger construction. This note records
the exact construction we intend to put forward for attack. Do not implement
before that review or an equivalent TLS/SEAT review.

## Construction

    K_bind = TLS-Exporter("EXPORTER-EMILIA-AUTH-BINDING-v1", empty_context, 32)

    tag = HMAC-SHA-256(K_bind, M)

`K_bind` is derived once per TLS connection and reused for every authentication
instance on it. The instance nonce lives in `M`, not in the exporter context,
so the verifier pays one exporter call per connection and cheap HMAC per
instance (O(1), not O(n) in concurrent streams). Connection-local state is
exactly the 32-byte `K_bind`; there is no per-instance key, derivation cache,
or nonce-to-key table.

## Frame M (fixed-schema, fixed-width, no length prefixes)

    offset  len  field
    0        1   version = 0x01
    1        1   presenter_role         enum { gate=0x01, agent=0x02, witness=0x03, ... }
    2       16   authentication_instance_nonce   128-bit random (meets the >=128-bit floor)
    18      32   relying_party_audience_digest   SHA-256(audience identifier)
    50      32   exact_action_caid               SHA-256
    82      32   evidence_digest                 SHA-256
    114      1   reserved = 0x00                 MUST be zero
    ----
    total: 115 bytes

The verifier reads exactly 115 bytes, HMACs them, compares in constant time.
No length fields, no variable widths, no padding, no parser state machine.
Extensibility is a new `version` byte with its own fixed layout, never a
variable field (IPv6-header discipline, not IPv4 options). The `reserved` byte
is a cheap malformed-frame reject and is mildly redundant with the version
discipline; keep it.

Audience is carried as a 32-byte SHA-256 digest, NOT the raw identifier
left-padded. Audience identifiers (URLs, SPIFFE IDs) routinely exceed 32 bytes;
truncating them into a fixed slot would let two distinct audiences occupy the
same frame position, which is an audience-substitution attack. The digest is
fixed-width for any input and collision-resistant.

## Invariants

1. The secret exporter output `K_bind` is never transmitted, logged, or placed
   in evidence.
2. The public RFC 9266 channel-binding value (`EXPORTER-Channel-Binding`) is
   NEVER used as an HMAC key. It is channel-binding data meant to be exposed;
   the key comes only from the separate `EXPORTER-EMILIA-AUTH-BINDING-v1`
   invocation.
3. `tag` is covered by the workload's asymmetric HTTP Message Signature; the
   relying party independently derives `K_bind` from its own TLS stack.
4. The instance nonce is a relying-party challenge consumed exactly once;
   consumption state is connection-local and dies with the connection.
5. Missing exporter access for the current connection yields INDETERMINATE,
   never a pass.
6. TLS 1.3 KeyUpdate does not rotate the exporter master secret and resumption
   yields a fresh one per connection, so `K_bind` is stable within a connection
   and unique across connections. No epoch handling.

Role prevents tag reflection between the two ends; audience digest covers
connection coalescing and virtual hosts; nonce separates concurrent instances;
CAID and evidence digest stop action and presentation substitution under a
valid channel.

## Design choice we present, not pose

Nonce-in-M is a decision with a rationale, not an open question: nonce-in-
context forces one exporter derivation per concurrent authentication (O(n) on a
100-stream connection); nonce-in-M derives `K_bind` once and is O(1). We
present that choice and its reason and invite the reviewer to break it, rather
than ask her to design it.

## Deployment truth (stated as correct behavior, not apology)

Where TLS terminates at a load balancer or proxy, the verifier cannot observe
the connection's exporter and the result is INDETERMINATE. That is the correct
answer, not a failure: the construction is meaningful exactly where termination
is local to the relying party (mutual-TLS service mesh, sidecar termination,
direct agent-to-agent), which is where high-value interactions already run.
INDETERMINATE for generic LB-terminated traffic is the protocol being honest
about what it can observe. A proxy deployment can reach full strength only if
the terminator exposes the exporter over an authenticated, trusted interface.

## Registration note

`EXPORTER-EMILIA-AUTH-BINDING-v1` is a distinctive private-use label for the
experimental phase. If the construction survives review and is implemented, an
IANA registration in the TLS Exporter Labels registry is required before any
non-experimental use.
