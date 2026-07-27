# Authorization Transition Record + EP Triggering Evidence

This runnable example maps an EP authorization receipt to the `user_approval`
trigger in Section 7.4 and WI-8 of
[`draft-kuehlewind-audit-architecture-00`](https://datatracker.ietf.org/doc/draft-kuehlewind-audit-architecture/).

```bash
node examples/authorization-transition-record/demo.mjs
```

The composition is intentionally narrow:

- the audit architecture owns the Authorization Transition Record, previous and
  new state, audit context, store, queries, attestation, and transparency;
- the record's `trigger.evidence_ref` points to an EP receipt by content digest;
- the auditor verifies the record under its pinned Auditing Service key and the
  EP receipt under separately pinned approver-directory and receipt-log keys;
- the auditor checks that the record's responsible actor is the receipt's named
  approver and that the receipt authorizes the exact action under review.

The example accepts the valid composition and refuses action substitution,
responsible-actor substitution, receipt substitution under a stable reference,
record tampering, and a record signed by an untrusted Auditing Service.

This is an individual composition example, not a claim of adoption by the draft
authors or any IETF group. It does not decide whether the state transition is
lawful, prove human perception, or replace the architecture's audit and
transparency machinery.
