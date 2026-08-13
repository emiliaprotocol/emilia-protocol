# Bounded Capability Receipts -05 staging packet

Upload only:

`UPLOAD-THIS/draft-schrock-ep-bounded-capability-receipts-05.xml`

Revision -05 defines an optional admission-control epoch profile for an
Emergency Authority Freeze inside one authoritative atomic state domain. It
serializes the freeze against reservation and provider entry, captures the
current epoch during reservation, and consumes the held amount when provider
entry is recorded. Outcome commitment does not debit the budget again.

The revision also defines authenticated idempotent freeze retries, separate
authority for restoration, wrong-holder retention, continued reconciliation of
operations that entered before a freeze, and an honest stale-admission window
for disconnected leased executors. It does not claim to stop computation, undo
an external effect, freeze independent state domains instantly, or prove that
an action was unauthorized merely because a receipt is absent.

The local admission-control epoch profile is implemented in the in-memory and
PostgreSQL reference stores for explicitly covered operations. The hostile
suite includes a live ephemeral PostgreSQL 17 race test for both freeze versus
provider-entry orderings. This is same-team implementation evidence, not an
independent reproduction, production deployment, disconnected-edge lease, or
portable signed freeze-event artifact. The included checker also runs an
executable editorial decision model for the normative race table and pins the
required source and hostile-test surfaces.

This packet is staged only. It has not been submitted to the Datatracker.
