# AE Challenge revision 07 private red-team candidate

This packet is private and unpublished. Do not upload it, announce it, or
describe it as live on the Datatracker.

Candidate source:

`UPLOAD-THIS/draft-schrock-ae-challenge-07.xml`

Revision -07 repairs the load-bearing defects found after -06:

- one owner-side transition joins expiry, replay/collision classification,
  nonce claim, and every applicable refusal-path capacity bucket;
- stateful-open capacity is transferred into the in-flight reservation and
  only the positive incremental delta is added;
- replay is scoped to a stable authenticated issuer identity plus nonce;
- nonce syntax now carries at least 128 bits when generated as required;
- the action profile and digest are one authenticated binding, and an exact-
  action profile covers every material authorization and effect field;
- audience namespace and alias semantics are pinned for the challenge lifetime;
- stateful issuance atomically registers the exact body and debits every
  applicable capacity bucket before exposure;
- follow-ups repeat the full requirement set unless a separately specified
  continuation profile authenticates all predecessor evidence and state;
- replay, collision, expiry, capacity refusal, and owner uncertainty have a
  total decision order;
- the current action is compared before claim, while the final executor fence
  remains explicitly outside AE-CHALLENGE;
- the HTTP section is only a 403 Problem Details challenge-response carrier,
  not a complete presentation protocol;
- HEAD is excluded from the body-carrying profile, and the 401, 403, 409, 429,
  502, 503, and 504 boundaries follow their HTTP semantics;
- the DMSC material is illustrative and does not claim a gateway profile;
- nested objects, top-level critical extensions, Retry-After conversion,
  confidentiality, diagnostics, and pre-owner anti-abuse budgets are explicit.

The finite same-team model explores four coordinated cap buckets, transfer of
stateful-open debits, tuple-safe replay keys, recovery fencing, and explicit
unsafe mutations. It is not a database isolation or storage-driver refinement
proof.

The current reference runtime is deliberately blocked from claiming production
-07 conformance. It does not implement atomic stateful issuance, authoritative
owner time, reservation finalization, fenced recovery, or a contract-tested
compound store. Boolean capability declarations and a callback-shaped method
are not evidence that a backend implements those semantics.

Publication remains blocked. The exact candidate requires a new validation
record after the implementation claims and finite-model evidence are narrowed,
the runtime safety repairs are complete, and an independent reviewer examines
the final frozen bytes. The render and validation files are evidence only
after regeneration from those bytes.
