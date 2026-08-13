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

The admission-control epoch profile is not yet implemented. The included
checker is an executable editorial decision model for the normative race table,
not an implementation-conformance result or a live PostgreSQL concurrency test.

This packet is staged only. It has not been submitted to the Datatracker.
