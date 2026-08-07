# Bounded Capability Receipts -02 upload packet

This is the retained exact-submission packet for
`draft-schrock-ep-bounded-capability-receipts-02`, published on 2026-08-06. It
is separate from the immutable August 3 publication provenance packet and is
not an upload or send instruction.

Revision -02 makes the multi-executor boundary explicit: aggregate guarantees
require one relying-party-pinned atomic state domain, while a deployment that
cannot provide that binding must restrict the scope to one executor or state a
per-executor limit. It also specifies optional per-action human authorization
composition through the exact exercise-action digest and cites Walter Hawkins's
adjacent attested-payment draft without importing its attestation or SCITT
trust model.

The TypeScript reference execution path now implements both -02 composition
rules. Aggregate accounting is reported only when the relying-party-pinned
state-domain digest matches an atomic-capable store; otherwise only an
explicitly pinned single-executor fallback is available. Optional per-action
human authorization is independently verified under relying-party pins and
must bind the exact exercise-action digest. Legacy calls are labeled
`local_store_only`, not aggregate. These integrations do not close the older
wire-format and complete-lineage conformance gaps listed in the draft.

The source, TXT, and HTML renders are retained for publication provenance. The
IETF archive is authoritative for the posted revision and rendered forms.
