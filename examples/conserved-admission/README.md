# Conserved-Admission Handoff Lab

Executable cases for **Section 7.8 of
[draft-dunbar-dmsc-gw-scenarios-gap-analysis-04](https://datatracker.ietf.org/doc/draft-dunbar-dmsc-gw-scenarios-gap-analysis/)**,
"Conserved Admission Across Gateway Boundaries."

```bash
node examples/conserved-admission/demo.mjs          # human-readable
node examples/conserved-admission/demo.mjs --json   # machine-readable
```

## The scenario

A field robot holds a **one-use authorization** for a consequential physical
action (close one named gas valve) and roams mid-task from Gateway A's domain
to Gateway B's, two independently operated gateways that share nothing: not a
store, not a log, not a trust decision. The conserved object is not session
context; it is the **exclusive ability to admit that one action**.

## What is mechanism and what is illustration

Every verification, exact-action binding, one-time consumption, refusal, and
revocation-status check is the repository implementation (EP-RECEIPT-v1 gate
check, tenant-scoped consumption ledger, EP-STATUS-v1). Each refusal reason
in the output is the one the mechanism produced.

The handoff coordination itself (the enablement record, the
dispose-before-enable ordering, the reconciliation record) is **lab code,
deliberately minimal**, because Section 7.8's finding is that no standard
mechanism for this transfer exists. The lab makes the gap and its failure
cases executable; it does not claim to close the gap.

## The cases, mapped to Section 7.8

| # | Case | 7.8 language it exercises | Outcome |
|---|------|---------------------------|---------|
| 1 | `copy-without-disposal-admits-twice` | "Copying the authorization ... is insufficient if both gateways can still admit the action" | the failure: 2 admissions, 2 executions |
| 2 | `conserved-handoff-admits-once` | "prevent the previous gateway from admitting before enabling the new gateway"; correlated records | 1 admission; records join by action digest + handoff id |
| 3 | `duplicate-delivery-refused` | "testable under duplicate delivery" | `replay_refused` at B |
| 4 | `concurrent-admission-at-most-once` | "concurrent admission attempts" | at most one admission under the race |
| 5 | `lost-acknowledgement-closed` | "lost acknowledgements ... An unresolved handoff must not be treated as permission to admit or retry" | 0 admissions; handoff closes unresolved |
| 6 | `revoked-during-handoff-refused` | "expiry or revocation during handoff" | `status_revoked` at B; A already disposed |
| 7 | `material-action-change-refused` | "material action changes" | `execution_binding_failed` at B |
| 8 | `enablement-is-not-evidence` | "preserve independent trust and policy evaluation at the receiving gateway" | `receipt_required` at B |

The property demonstrated is **at-most-once admission of a specific action**,
not exactly-once physical execution: case 5 shows the acceptable failure
(losing an in-flight authorization and closing) and case 1 shows the failure
the profile must prevent (resurrecting or duplicating one).

## Where each invariant comes from

- **Exact-action identity**: the gate's execution binding over the receipt's
  signed claim (`execution_binding_failed` when the observed action drifts) —
  the CAID role in the draft's reference list.
- **One-time admission within one domain**: each gateway's own consumption
  ledger (`reserve` / `commit` / `consume`, `replay_refused` on re-use) — the
  AEB role.
- **Revocation reaching the receiver mid-handoff**: an authenticated terminal
  `revoked` EP-STATUS-v1 statement, refused by outcome, never by hearsay.
- **Source-side disposal before enablement**: the RFC 4067 replay model,
  applied to admission authority instead of mobility context. This ordering
  is the lab's one coordination rule and is exactly the piece Section 7.8
  identifies as unstandardized.

Related labs: [`examples/cross-gateway/`](../cross-gateway/) (one artifact
verified independently at two gateways, no transfer of admission) and
[`examples/handoff/`](../handoff/) (agent context-window handoff via receipt
chains, a different boundary).

## Tests

```bash
npx vitest run tests/conserved-admission.test.ts
```
