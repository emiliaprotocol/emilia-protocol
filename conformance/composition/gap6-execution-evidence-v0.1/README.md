<!-- SPDX-License-Identifier: Apache-2.0 -->
# Execution-Layer Evidence and field-origin composition profile

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

## M01 field-origin evidence

The profile now adds a fourth, narrower claim at the admission boundary:
where a pinned issuer says each exact action field came from, and whether the
field was read as immutable data or as a snapshot of mutable state. The signed
`EP-FIELD-ORIGIN-v0.1` object is bound to the exact observed action and to a
relying-party-pinned profile.

Effect-relevant control fields may come only from the origin classes the
profile permits. Derived control values must name the exact pinned transform
id, version, and digest. `unknown` stays unknown. Untrusted bytes may still
fill a bounded data field such as `memo`, which keeps the rule discriminating
instead of turning it into a blanket content ban.

The prior art is [CaMeL, "Defeating Prompt Injections by Design"](https://arxiv.org/abs/2503.18813),
which separates trusted control flow from untrusted data inside an agent
runtime. This profile does not claim to solve prompt injection. Its narrower
delta is a signed field-origin assertion evaluated at executor admission and
carried as evidence that a relying party can verify afterward.

## The demonstration boundary

The exact action is a finance-operations boundary: a **vendor bank-detail
change** (the classic business-email-compromise target), dual-controlled by
two named approvers under a user-verification-gated ceremony. Routing and
account numbers enter the evidence only as digests.

## Run it

```bash
npm ci --ignore-scripts
node conformance/composition/gap6-execution-evidence-v0.1/run.mjs          # demonstration
node conformance/composition/gap6-execution-evidence-v0.1/run.mjs --json   # full report
npm run pilot:finance-field-origin                                      # paid-pilot bundle
```

The install step resolves the repository-local packages pinned by the root
lockfile. `--ignore-scripts` is sufficient for this runner and avoids invoking
unrelated lifecycle scripts during a clean-clone reproduction.

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
| 9 | `m01-injected-email-payee-change-refused` | proven | refused `field_origin_control_untrusted:/vendor_id` | not entered |
| 10 | `m01-webpage-target-change-refused` | proven | refused `field_origin_control_untrusted:/erp` | not entered |
| 11 | `m01-transformed-control-substitution-refused` | proven | refused `field_origin_transform_unpinned:/new_account_digest` | not entered |
| 12 | `m01-unknown-origin-refused` | proven | refused `field_origin_unknown:/change_ticket` | not entered |
| 13 | `m01-profile-downgrade-refused` | proven | refused `field_origin_profile_mismatch` | not entered |
| 14 | `m01-bounded-untrusted-memo-admitted` | proven | admitted | executed; untrusted memo remained bounded data |

Every refusal reason in the output is the one the mechanism produced, not one
this file chose. The executor runs exactly five times across all fourteen
cases. Only the bounded-data M01 case reaches the effect among the six M01
cases.

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
- Field-origin evidence authenticates a pinned issuer's assertion about field
  provenance and snapshot caveats. It does not establish source truth, detect
  prompt injection, authorize the action, or prove an external effect.
- A trust key carried inside a pilot bundle is not self-authenticating. An
  external verifier must pin that key out of band.

## Paid-pilot bundle

`npm run pilot:finance-field-origin` writes the signed field-origin evidence,
the pinned profile and public trust key, the exact observed action, the Gate
hash chain, the deterministic fourteen-case report, an auditor workpaper, an
underwriter control attestation, and a digest manifest. The generated
`PILOT-REPORT.md` explains the five refusals and the bounded-data positive
case in buyer language while preserving the claim boundary.

Verify a bundle without network access from the source commit recorded in its
manifest:

```bash
npm run verify:finance-field-origin-pilot -- /path/to/pilot-kit
```

## Tests

```bash
npx vitest run conformance/composition/gap6-execution-evidence-v0.1/run.test.mts
npx tsx --test conformance/composition/gap6-execution-evidence-v0.1/pilot-kit.test.mts
```
