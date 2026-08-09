# AE Challenge revision 05 candidate

This isolated candidate is derived from the published
`draft-schrock-ae-challenge-04` source. Revision -04 remains unchanged. The
upload source for the next revision is:

`UPLOAD-THIS/draft-schrock-ae-challenge-05.xml`

Revision -05 closes the state-exhaustion and retry-semantics findings raised
by Sumit P. Ahuja after publication of -04.

It also closes the overlap with OAuth Transaction Authorization Challenge.
When the missing object is a native transaction-specific OAuth grant, that
flow remains primary: its signed challenge, 401 response, transaction ID,
authorization-server decision, access token, and replay state are not replaced
by AE-CHALLENGE. AE remains the transport-neutral description of other missing
or stale authorization evidence. Both can coexist only through an application
profile that defines their action join and keeps their replay domains separate.
An explicit hostile case requires refusal when AE evidence is presented without
the native OAuth grant.

`retry_timing` is explicitly non-critical: it changes pacing, not the meaning
of the refusal. `not_before` is only an earliest presentation time and makes
no promise about capacity, evidence sufficiency, admission, or execution.
Carrier-level overload handling remains available for clients that ignore
timing guidance.

The core now permits two issuance modes. A relying party can durably register
the complete body before exposure, or use a profile-defined,
issuer-authenticated self-describing body. The latter reduces unanswered
outstanding state but does not eliminate replay state: the first returned
presentation still atomically claims its nonce before evidence evaluation.

Every authoritative replay domain has a finite aggregate state bound, with
per-presenter, per-audience, and per-tenant bounds where applicable. At the cap, an issuer
does not create another stateful challenge. If a self-describing return cannot
claim replay state, it receives no evidence evaluation and no admission. Live
in-flight and unexpired consumed nonces cannot be evicted to make room.

Verifier replicas share one atomic replay domain or an exclusive deterministic
shard. Store unavailability, partition, or uncertain claim results fail closed
and never fall back to process-local state.

Four conformance cases pin cap behavior, self-describing replay exhaustion,
cross-replica concurrency, and non-eviction of live replay state. The HTTP
binding maps state exhaustion to 503 without an `evidence_challenge` member.

The DMSC boundary is unchanged: AE-CHALLENGE communicates evidence
requirements but does not transfer admission ownership or prevent
cross-gateway double admission.
