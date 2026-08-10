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
- replay, collision, expiry, capacity refusal, and owner uncertainty have a
  total decision order;
- the current action is compared before claim, while the final executor fence
  remains explicitly outside AE-CHALLENGE;
- the HTTP section is only a 403 Problem Details challenge-response carrier,
  not a complete presentation protocol;
- 401, 403, 409, 429, and 503 boundaries follow their HTTP semantics;
- the DMSC material is illustrative and does not claim a gateway profile;
- nested objects, top-level critical extensions, Retry-After conversion,
  confidentiality, diagnostics, and pre-owner anti-abuse budgets are explicit.

The finite same-team model explores four coordinated cap buckets, transfer of
stateful-open debits, tuple-safe replay keys, recovery fencing, and explicit
unsafe mutations. It is not a database isolation or storage-driver refinement
proof.

The current reference runtime is deliberately blocked from claiming production
-07 conformance because it does not implement the compound claim-and-capacity
transition. Its production capability gate requires
`compoundClaimAndCapacity()`, which the current adapters do not implement.

Publication remains blocked until the packet is rebuilt from frozen source,
all recorded gates are rerun, and an independent HTTP/security reviewer has
reviewed the exact bytes. The render and validation files are evidence only
after they have been regenerated from the final XML.
