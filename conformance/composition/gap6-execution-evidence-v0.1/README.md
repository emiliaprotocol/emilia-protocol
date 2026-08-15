<!-- SPDX-License-Identifier: Apache-2.0 -->
# Execution-Layer Evidence composition profile, first cut

Status: source-pinned discussion artifact for review by the authors of
`draft-chen-oauth-agent-authz-use-cases-02`. It is not an Internet-Draft, not a
specification of that draft, and not an interoperability or endorsement claim.
Running it externally reproduces these pinned checks; it is not an independent
implementation result.

## What Gap 6 asks for

Section 5 of `draft-chen-oauth-agent-authz-use-cases-02` names the gap: the
OAuth framework "lacks a standard mechanism for generating Execution-Layer
Evidence—a non-repudiable, cryptographic proof of a user's explicit consent
for a specific, high-risk action at the moment it occurs," observing that
"grant-layer tokens prove potential, not the legitimacy of a specific,
executed transaction." Use Case 11 adds that final-action evidence "must bind
the specific payment details (amount, recipient) to the full, verifiable
delegation chain," creating "an undeniable record that the specific
transaction was legitimate and explicitly sanctioned."

## The three-claim separation

That requirement compresses three different claims, and no single artifact can
honestly prove all three:

| Claim | Question | Evidence that answers it |
|---|---|---|
| **Approval** | What did the named human(s) explicitly consent to? | The authorization artifact, verified under relying-party-pinned anchors (issuer key, approver keys, quorum policy) |
| **Admission** | Did the enforcement point in front of the executor admit that exact action, once? | The boundary's own decision record: exact-action binding recomputed from executor-observed material, one-time consumption in the boundary's own ledger |
| **Execution** | Was the effect entered, and with what outcome? | The execution record's cryptographic binding to the admitted decision; an entered effect with no answer is `INDETERMINATE`, never a retry |

A receipt proves the first claim. Admission and execution are separate claims
with separate evidence. This profile makes the separation executable: every
case reports a verdict per claim, so the difference between "approved,"
"admitted," and "occurred" is visible in the output rather than asserted in
prose.

## The demonstration boundary

The exact action is a finance-operations boundary: a **vendor bank-detail
change** (the classic business-email-compromise target), dual-controlled by
two named approvers under a user-verification-gated ceremony. Routing and
account numbers enter the evidence only as digests.

## Run it

```bash
node conformance/composition/gap6-execution-evidence-v0.1/run.mjs          # demonstration
node conformance/composition/gap6-execution-evidence-v0.1/run.mjs --json   # full report
```

One execution emits three outputs:

1. `report.json`: the machine-verifiable conformance report, pinned to the
   profile version and carrying a deterministic `results_digest` over the
   case verdicts (volatile metadata such as timestamps and runner identity is
   reported beside the digest, never inside it).
2. stdout: the finance-operations demonstration.
3. `reproduction-receipt.json`: a compact receipt stating the digest this run
   produced and whether it matches the committed reference
   (`report.reference.json`). An external operator can regenerate it
   independently and paste it into their own implementation-status section.

## The load-bearing cases

| # | Case | Approval | Admission | Execution |
|---|------|----------|-----------|-----------|
| 1 | `through-exact-human-exact-action-once` | proven (2 named approvers) | admitted, once | executed, bound to the admitted decision |
| 2 | `missing-human-evidence` | **indeterminate** (nothing presented) | refused `receipt_required` | not entered |
| 3 | `fabricated-approval-refused` (the agent clicks Approve) | not credited | refused `assurance_too_low` | not entered |
| 4 | `wrong-approver-refused` | not credited under pinned anchors | refused `receipt_rejected:untrusted_or_invalid_signature` | not entered |
| 5 | `action-substitution-refused` | proven, for a different action | refused `execution_binding_failed` | not entered |
| 6 | `replay-refused` | still proven (verification is not admission) | refused `replay_refused` | not entered |
| 7 | `lost-acknowledgement-indeterminate` | proven | admitted, then committed | **indeterminate**, bound to the admitted decision; blind retry refused |
| 8 | `false-execution-claim-rejected` | proven | admitted | claim not credited: asserted result binds no admitted decision |

Every refusal reason in the output is the one the mechanism produced, not one
this file chose. The executor runs exactly four times across all eight cases.

## Limits (what each output does not prove)

- The approval artifact proves consent to the exact action material. It does
  not prove the action was admitted or occurred.
- The admission decision proves this boundary's verdict under its own pinned
  anchors and ledger. It does not prove any other boundary's verdict, and a
  verdict does not travel as evidence.
- The execution record proves the effect was entered under a specific admitted
  decision and what the boundary observed of its outcome. It does not prove
  real-world settlement beyond the provider's answer, and when the provider
  gives no answer the record says so (`INDETERMINATE`) rather than guessing.
- The one-time-consumption guarantee is scoped to one boundary's ledger.
  Cross-gateway authority transfer is a distinct, open problem (see
  `draft-dunbar-dmsc-gw-scenarios-gap-analysis-04`, Section 7.8, and
  `examples/conserved-admission/`).

## Tests

```bash
npx vitest run conformance/composition/gap6-execution-evidence-v0.1/run.test.mts
```
