# Bounded Capability Receipts -03 candidate

This isolated candidate is derived from the immutable posted
`draft-schrock-ep-bounded-capability-receipts-02` source. It is staged work,
not a Datatracker upload or publication instruction.

Revision -03 adds explicit revocation inheritance to the existing delegation
model. Every signed capability states `revocation_mode` as `direct` or
`cascade`. Direct revocation leaves authority already transferred to a
registered child independently valid. Cascade revocation blocks future
reservations and child allocations throughout the descendant lineage.

Immediate cascade claims require the ancestor revocation transition and the
descendant reservation to serialize in the same authoritative atomic state
domain. Revocation that wins the race refuses the reservation; a reservation
that wins remains owned and reconcilable. Missing current ancestor state
refuses before provider entry. Cached or eventually consistent status cannot
be represented as immediate cascade enforcement.

The revision does not define revocation distribution or cross-domain admission
handoff. It also does not treat grace or completion after revocation as an
implicit policy: continued or wind-down authority requires a separate bounded
authorization.

The same-team TypeScript reference stack now signs and requires the new field,
records parent lineage, traverses complete ancestor state, serializes durable
PostgreSQL revocation and reservation, quarantines legacy rows without an
explicit mode, and exercises direct, cascade, unavailable-lineage, child
allocation, and both race orderings. A bounded TLA+ model covers the same
direct/cascade and ordering distinction. This is implementation evidence in
one authoritative atomic state domain, not independent interoperability,
revocation distribution, or cross-domain cascade enforcement.
