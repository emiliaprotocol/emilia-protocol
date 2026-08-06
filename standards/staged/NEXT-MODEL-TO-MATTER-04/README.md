# Model-to-Matter -04 upload packet

This is the isolated candidate packet for
`draft-schrock-model-to-matter-04`. Nothing in this directory has been filed.
The posted `-03` source and the August 3 publication-provenance packet remain
unchanged.

Upload only after human review:

- `UPLOAD-THIS/draft-schrock-model-to-matter-04.xml`

Revision -04:

- adds `physical_state_attestation` as the seventh required pre-execution
  evidence role;
- binds the claimed measurement to the exact action and the executor-pinned
  precondition set;
- requires relying-party-pinned measurement-age and validity-duration limits;
- requires a sensor control domain distinct from the executor, not merely a
  second key;
- refuses missing, stale, mismatched, or negative attestation state; and
- fixes the signed validity window deterministically from the measurement
  instant and the executor-pinned duration, preventing window-only renewal;
- states that the signature evidences a source claim, not physical truth,
  calibration, placement, unchanged state through execution, or safety.

The reference Model-to-Matter clearance path implements all seven roles and
binds the compiled Reliance Program and evidence-requirement digests into each
clearance. This is synthetic reference and conformance evidence, not a wet-lab
deployment or a claim of physical truth. Filing remains a separate human
decision and would publish an Experimental individual Internet-Draft, not an
RFC, working-group document, IETF consensus, or IETF endorsement.
