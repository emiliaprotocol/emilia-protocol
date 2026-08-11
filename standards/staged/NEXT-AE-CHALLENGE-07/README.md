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
- issuance, claim, and finalization preserve one authenticated-presenter scope,
  pinned capacity limits, and owner-authoritative transaction time;
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
- malformed objects are rejected before owner allocation; raw HTTP parsing must
  reject duplicate members before object-level helpers run;
- PostgreSQL writes use deterministic bytewise key order while locked-row
  validation is independent of database collation;
- caller-selected production follow-up nonces are refused before claim, and a
  malformed follow-up is terminalized without silently stranding authority.

The finite same-team model explores four coordinated cap buckets, transfer of
stateful-open debits, tuple-safe replay keys, recovery fencing, and explicit
unsafe mutations. It is not a database isolation or storage-driver refinement
proof.

The reference runtime now implements the stateful owner path through one
factory-created owner state machine and a PostgreSQL transaction backend. The
owner uses database transaction time, registers issuance before exposure,
claims and reserves atomically, finalizes a terminal result or bound follow-up
atomically, and fences recovery with a generation-bound owner token. Production
evaluation refuses copied stores and caller-declared capability booleans. The
packed package exposes the PostgreSQL backend and its generated declarations.

This remains a same-team reference, not an independently reproduced
implementation or a deployed-database audit. The finite model is small-bound
scenario evidence and is labeled that way. Self-describing issuance, database
role configuration, expiry collection, authenticated alias resolution,
preallocated shard quotas, and pre-owner abuse controls remain deployment or
future-profile work unless separately implemented and tested.

The frozen candidate passes its local publication, type, package, formal-
runtime, security-case, and repository test gates. It is fit for external
review, but remains private and unpublished pending an explicit filing
decision. No upload or Datatracker claim is implied by this packet.
