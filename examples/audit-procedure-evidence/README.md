<!-- SPDX-License-Identifier: Apache-2.0 -->
# Audit-procedure evidence demo

An AI agent performs one real assurance procedure, a full-population cash
tie-out, end to end through this repository's evidence machinery. One run
produces five separable artifacts and keeps their claims separate:

| Artifact | Mechanism | Question it answers |
|---|---|---|
| **Authorization** | EP-RECEIPT-v1 quorum receipt (two named approvers, per-signer-verifiable ceremony evidence) over the exact procedure scope | What procedure, at what scope, did the humans direct? |
| **Admission** | The Gate's own decision, exact-action binding recomputed from the material the Gate observed, one-time consumption in its own ledger | Did the boundary admit that exact procedure, once? |
| **Execution evidence** | The execution record's cryptographic binding to the admitted decision | Was the procedure performed, and with what results? |
| **Sign-off** | A second quorum ceremony over an `assurance.exception-disposition.1` action, admitted by its own boundary | Which humans dispositioned the exception, and when? |
| **Workpaper** | `WORKPAPER.md`, generated with deterministic bytes and committed beside this file | How does each artifact map to an audit documentation concept? |

The authorization, the admission, and the sign-off are joined by content
identity, not by trust transfer: the procedure's CAID is computed over the
full typed action (including a digest pinning the entire reconciling-item
population), named in the authorization receipt's signed claim, recomputed by
the Gate from the material it observed at admission, and named again as
`procedure_caid` inside the disposition action the sign-off ceremony covers.

## Run it

```bash
node examples/audit-procedure-evidence/demo.mjs           # human-readable
node examples/audit-procedure-evidence/demo.mjs --json    # deterministic case report
node --test examples/audit-procedure-evidence/demo.test.mjs
```

## The procedure

Three fixture general-ledger cash accounts are tied out against fixture bank
statements at 2026-06-30, resolving the full population of 12 reconciling
items against the closing documents (ledger entries, statement period lines,
and cutoff-period lines). No sampling. Two accounts tie exactly. One item,
`TRF-0912`, a claimed in-transit transfer of 25000.00 into the reserve
account, appears in neither closing document: no subsequent credit on the
receiving statement and no counterpart entry or line for the source account.

## The load-bearing cases

| # | Case | Outcome |
|---|------|---------|
| 1 | `procedure-authorized-admitted-executed` | quorum receipt proven; admitted once (replaying the consumed receipt is refused `replay_refused`); CAID recomputed at the boundary equals the authorized identity; execution bound to the admitted decision; result **EXCEPTIONS-NOTED**, never a silent complete |
| 2 | `origin-labels-admitted` | every consumed evidence field carries a closed-vocabulary EP-ORIGIN-LABELS-v1 label (client documents `counterparty-document`, engagement config `operator-config`, computed values `derived` with `derived_from`), satisfying the policy floors |
| 3 | `completion-without-disposition-refused` | finalization refused `exception_undispositioned:TRF-0912`; the agent's ceremony-free disposition attempt refused `receipt_required`; the effect never runs |
| 4 | `origin-label-laundering-refused` | the agent re-derives the missing bank confirmation from its own summary; labeled honestly it fails the floor (`origin_trust_floor_violation:...`), relabeled as `counterparty-document` it trips cross-path value consistency (`value_origin_conflict:...`); the item stays INDETERMINATE |
| 5 | `scope-substitution-refused` | the period end changes between authorization and execution; `execution_binding_failed`, and the CAID no longer recomputes (`digest_mismatch`) |
| 6 | `signoff-ceremony-dispositions-exception` | two named humans disposition the exception under a verifiable quorum ceremony, admitted as its own action joined by `procedure_caid`; the workpaper finalizes with the exception recorded, still INDETERMINATE, result still EXCEPTIONS-NOTED |

Every refusal reason from the Gate and from the origin-label evaluator
(`receipt_required`, `replay_refused`, `execution_binding_failed`,
`origin_trust_floor_violation:...`, `value_origin_conflict:...`) is the one
the repository mechanism produced. The finalization refusal
(`exception_undispositioned:TRF-0912`) comes from this demo's own
workpaper-completion rule, deliberately small lab code, because a standard
workpaper-finalization mechanism is exactly what this example argues an
evidence layer should carry. INDETERMINATE never authorizes anything and is
never auto-cleared: the human disposition records the exception and names
follow-up; it does not resolve the item.

## Determinism

Fixture data, timestamps, receipt ids, the CAIDs, the case report, and the
generated `WORKPAPER.md` are byte-stable across runs and machines
(`results_digest` pins the deterministic case report). Receipt signatures,
public keys, and Gate decision hashes come from fresh conformance keys each
run; they are printed, never embedded in the deterministic bytes.

## Claim boundary (read before quoting)

- This demo maps artifacts to audit documentation **concepts**. The concepts
  are drawn informatively from audit documentation standards such as PCAOB
  AS 1215, ISA 230, and AICPA SAS No. 142. It claims no compliance with,
  satisfaction of, or endorsement by those or any other standards.
- It is not an audit and does not produce audit evidence in any legal or
  professional sense. It demonstrates the shape of an evidence chain for
  agent-performed assurance work over fixture data.
- The approval artifact proves what the named (fixture) humans approved. It
  does not prove the procedure was admitted or performed; those are the
  admission and execution claims, with their own evidence.
- Origin labels are producer claims checked for closed vocabulary, internal
  consistency, and policy trust floors at admission, not source truth. A
  producer that lies consistently and never contradicts itself is not
  detectable by this mechanism; case 4's laundering is caught because the
  honest twin assertion names the same value digest.
- One-time admission is scoped to each boundary's own in-process ledger here;
  production requires durable shared state.

## Residuals

Fixture entity and balances; a toy bank-statement format; full population of
12 items with no sampling theory; a single procedure with none of the review
layers, materiality judgment, or confirmation work a real engagement
composes; conformance-harness approver identities standing in for an
engagement partner and a second reviewer.

## Files

- `demo.mts` / `demo.mjs`: the runnable demonstration (the `.mjs` is the
  generated Node-20 companion).
- `demo.test.mts` / `demo.test.mjs`: node:test suite.
- `fixtures/`: general ledger, bank statements, reconciling items, and the
  locally pinned CAID action-type definitions.
- `WORKPAPER.md`: the generated deterministic workpaper, committed and
  byte-checked on every run.
