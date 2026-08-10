# AE Challenge revision 07 hostile-review candidate

This isolated packet is a candidate for `draft-schrock-ae-challenge-07`. It is
not published and must not be described as live on the Datatracker. It starts
from the exact published -06 source and repairs defects found by a hostile
state-machine review.

Upload candidate after all gates pass:

`UPLOAD-THIS/draft-schrock-ae-challenge-07.xml`

The load-bearing repair is one atomic owner-side transition joining exact-body
nonce claim to every applicable refusal-path capacity reservation. Separate
steps can either reserve twice for concurrent copies of one nonce or burn a
nonce when capacity is unavailable. The transition has six closed outcomes:
claimed-with-capacity, exact-body-replay, body-collision, capacity-refused,
expired, and unavailable.

The revision also:

- scopes replay to authenticated issuer identity plus nonce and makes
  `challenge_id` correlation-only;
- binds the authenticated returning presenter to the challenge audience;
- requires current exact-action rederivation before state claim;
- requires one transaction domain or bounded preallocated quotas for every
  hard-cap bucket;
- fences recovery so a stale worker cannot publish state after reassignment;
- rejects duplicate JSON members and requires finite pre-cryptographic limits;
- defines deterministic complete-body digesting and portable JSON integer
  bounds;
- makes all evidence entries and predicates conjunctive while treating
  profiles within one entry as alternatives;
- requires retry timing plus maximum jitter to remain before expiry;
- hardens obtain hints against SSRF and credential forwarding;
- regenerates follow-ups only from the current action and live policy; and
- removes reliance on an unpublished DMSC section number.

The same branch repairs two reference-runtime defects that predated the new
compound transition: an action-mismatched presentation no longer consumes the
valid challenge, and the durable replay key no longer includes the
correlation-only `challenge_id`.

The new compound capacity transition remains unimplemented and is labeled that
way in Implementation Status. A finite same-team model checks selected logic
properties and includes mutations for split claim/reservation, nonce burn,
cross-shard over-allocation, and stale-owner finalization. It is not a database
refinement proof or independent implementation evidence.
