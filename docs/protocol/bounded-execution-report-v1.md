<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-BOUNDED-EXECUTION-REPORT-v1

`EP-BOUNDED-EXECUTION-REPORT-v1` is a relying-party-signed, canonical snapshot
of occurrences that Gate recorded for one verified
`EP-BOUNDED-EXECUTION-PROGRAM-v1`. It binds the tenant, program ID and version,
program digest, subject, audience, report interval, generation time, complete
normalized `ExecutionProgramRuntimeState` digest, normalized occurrence
inventory digest, per-node buckets, budget use, runtime status, and
supersession links.

This report is not an authorization to execute.

## Source and completeness boundary

Construction requires the accepted result of `verifyBoundedExecutionProgram`,
and one closed `ExecutionProgramReportSnapshot` returned by
`readExecutionProgramReportSnapshot`. That public store read returns the
runtime state and complete retained occurrence inventory for exactly one
tenant and program digest from one transactionally consistent read. It orders
occurrences by `(node_id, occurrence_id)`, bounds the read by the signed
`max_total_occurrences`, and supplies a deterministic SHA-256 snapshot marker.
The report binds that marker as well as independently normalized runtime and
inventory digests.

The runtime's monotonic `total_occurrences` must equal the inventory length.
Every occurrence must bind the same tenant and program, reference a declared
node, carry that node's exact charges, and reconcile to the runtime's reserved
and consumed budgets. A missing, truncated, reordered, cross-tenant,
cross-program, over-ceiling, or marker-substituted snapshot fails closed.

The report interval contains program registration and every supplied
occurrence creation/update represented by the snapshot. The generation time is
at or after the interval end. This is a full program-to-date runtime snapshot,
not an arbitrary slice whose omitted earlier state could still consume budget.

The inventory digest covers each complete occurrence record in UTF-8 byte order
by `(node_id, occurrence_id)`. The runtime-state digest covers the complete
normalized `ExecutionProgramRuntimeState`, including its embedded verified
program, authenticated status metadata, total occurrence count, budgets, and
supersession state.

The signed program includes `max_concurrent_effects`. Report construction
reconciles the number of `INVOKING` and `INDETERMINATE` occurrences against
that ceiling. An `INDETERMINATE` occurrence remains an open effect for this
purpose until authenticated reconciliation records `COMMITTED` or
`PROVEN_NOT_COMMITTED`.

## Deterministic node buckets

Each program node appears once in UTF-8 byte order:

- `terminal_recorded_outcomes` contains occurrence IDs and the exact recorded
  `COMMITTED` or `PROVEN_NOT_COMMITTED` provider outcome.
- `unresolved_post_entry` preserves whether Gate recorded `INVOKING` or
  `INDETERMINATE`. “Post-entry” here means after Gate's begin boundary consumed
  the execution right. `INVOKING` does not prove that the provider received a
  request. `INDETERMINATE` preserves uncertainty; reconciliation does not by
  itself prove event time.
- `released_pre_entry` contains `RELEASED` occurrences. These did not consume
  attempt budget. They remain in the monotonic retained inventory and count
  against the signed program-wide `max_total_occurrences`, but no longer occupy
  the node's reusable `max_occurrences` capacity.
- `never_attempted` contains still-`RESERVED` occurrence IDs and the count of
  node occurrence capacity for which Gate has no occurrence record. This is
  descriptive, not a claim that all unallocated node capacity is currently
  executable; the program-wide ceiling, budgets, dependencies, status, expiry,
  and fresh authorization checks still apply.

Budget rows are ordered by `budget_id` and bind `unit`, `limit`, `reserved`,
`consumed`, and `remaining`.

## Signature and verifier-owned context

The relying party signs the closed body with Ed25519 under the shared canonical
JSON risk-artifact construction:

```text
signature_input = UTF8("EP-BOUNDED-EXECUTION-REPORT-v1" || 0x00 || body_jcs)
```

Verification accepts only an out-of-band RP key pin and requires the caller to
pin the expected report ID, RP, tenant, program ID/version/digest, subject,
audience, interval, runtime-state digest, occurrence-inventory digest,
report-snapshot marker, verification time, and maximum report age. Presented
issuer or key material never selects its own trust context. Unknown fields,
accessors, sparse arrays, non-Ed25519 keys, malformed signatures, and
substitutions fail closed.

## Experimental reference vectors

`conformance/vectors/bounded-execution-report.v1.json` contains deterministic
known-answer canonical bytes, Ed25519 signature, report digest, replay context,
and hostile mutations. Regenerate or check it with:

```bash
node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-report.mjs
node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-report.mjs --check
```

These are same-team experimental reference vectors against this repository's
implementation. They are not independent or cross-language conformance,
interoperability, standardization, or certification evidence.

## Claim boundary

The artifact reports Gate-recorded program occurrences only. It does not prove:

- external effect truth or event chronology;
- that the bounded program is safe, lawful, correct, or complete;
- complete mediation of all mutation paths; or
- the absence of actions performed outside Gate.

The concurrency count is Gate-recorded admission state, not proof that an
external provider is or is not still processing the request.

In particular, “executed outside the plan” is not claimed by this artifact.
That comparison requires a separately signed external inventory root with its
own completeness and capture-topology boundary. No such root is embedded or
inferred here.
