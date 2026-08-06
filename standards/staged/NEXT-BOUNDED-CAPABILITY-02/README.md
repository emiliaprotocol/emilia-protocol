# Bounded Capability Receipts -02 upload packet

This is an isolated working packet for a potential maintenance revision of
`draft-schrock-ep-bounded-capability-receipts-01`. It is separate from the
immutable August 3 publication provenance packet and is not an upload or send
instruction.

Revision -02 makes the multi-executor boundary explicit: aggregate guarantees
require one relying-party-pinned atomic state domain, while a deployment that
cannot provide that binding must restrict the scope to one executor or state a
per-executor limit. It also specifies optional per-action human authorization
composition through the exact exercise-action digest and cites Walter Hawkins's
adjacent attested-payment draft without importing its attestation or SCITT
trust model.

The source is the authoritative working artifact. TXT and HTML renders are
generated locally for review. Filing remains a separate human decision.
