# AE Challenge revision 06 publication-provenance packet

This isolated packet preserves the exact source and review artifacts for
`draft-schrock-ae-challenge-06`, published on 2026-08-10. It is not an upload
candidate; the immutable IETF archive is authoritative. The submitted source
retained for provenance is:

`UPLOAD-THIS/draft-schrock-ae-challenge-06.xml`

Revision -06 closes three connected refusal-path findings raised by Sumit P.
Ahuja after publication of -05.

First, every applicable hard state cap now binds through an atomic reservation
or debit before native evidence verification and local policy evaluation. A
read-only capacity check followed by expensive evaluation is insufficient
because capacity can race between the check and the later allocation.

Second, a binding capacity refusal controls the response even when evidence is
also missing, stale, or unverifiable. The relying party performs no native
evidence verification and returns no follow-up challenge, stateless requirement
list, obtain hint, or other evidence-sufficiency detail. This prevents overload
handling from becoming a policy-discovery oracle.

Third, deterministic replay sharding now has an explicit classification rule.
The owner is derived from issuer-protected challenge state. Only the
authoritative owner's already-claimed result is replay. A timeout, partition,
uncertain result, or failure to reach that owner is temporary unavailability,
not attacker replay, and never falls back to local state.

The HTTP binding maps binding capacity exhaustion and replay-owner
unavailability to 503 without `evidence_challenge` or policy hints. It can
include `Retry-After` without disclosing authorization requirements.

The packet preserves the existing OAuth non-substitution, DMSC ownership,
retry-pacing, and bounded-state boundaries from -05. The implementation-status
appendix states that the new -06 requirements are not yet implemented and makes
no independent-implementation claim.

The retained XML and TXT are byte-for-byte identical to the immutable IETF
archive artifacts. The XML SHA-256 is
`aa189344c491948a1df2d18d9bff529d696e618ebb2f73ebe607445031744433`.
