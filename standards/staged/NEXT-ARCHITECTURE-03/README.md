# EMILIA Protocol Architecture -03 staging packet

Submitted XML:

`UPLOAD-THIS/draft-schrock-ep-architecture-03.xml`

Revision -03 aligns the architecture with the implemented consequence boundary:
reservation holds authority, provider entry moves the held amount to consumed,
and outcome commitment records the result without spending the authority again.

It also describes Emergency Authority Freeze as a consequence-owner control
inside one authoritative atomic state domain. The architecture distinguishes
freeze from agent termination, separates restoration authority, preserves
reconciliation evidence for already-entered operations, and states the
stale-admission window for disconnected leased executors. It does not claim
instant global freeze, reversal of physical effects, or coverage of provider
paths that bypass the consequence owner.

Published September 6, 2026. Author confirmation completed; public IETF XML matches this packet exactly. Retained for publication provenance, not re-upload.
