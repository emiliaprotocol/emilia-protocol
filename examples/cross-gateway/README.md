<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cross-Gateway Evidence Lab

Two agent gateways in separate administrative domains enforce policy over one
consequential action, with one human-approval artifact between them. This is
the runnable form of a requirement discussed in agent-gateway gap analyses:
when Gateway B receives a consequential action through Gateway A, and Gateway
B's local policy requires human approval, Gateway A carries or references
evidence binding that approval to the exact action and its material
parameters, and Gateway B evaluates that evidence under its own trust anchors
and records a separate enforcement decision.

```zsh
node examples/cross-gateway/demo.mjs          # narrated run
node examples/cross-gateway/demo.mjs --json   # machine-readable result
```

Eight cases, one executor, exactly one execution:

1. `a-refuses-without-evidence`: the first enforcement point fails closed with
   the check named (`receipt_required`).
2. `one-artifact-two-independent-verifications`: Gateway A validates and
   records; Gateway B re-verifies the same artifact under its own pinned keys
   and its own consumption ledger, executes once, and records its own
   decision. The two audit records join by the shared action digest.
3. `decision-does-not-travel`: Gateway A's genuine allow verdict, offered
   without the artifact, is refused at Gateway B. A gateway's decision is not
   presentable evidence.
4. `tampered-in-transit-refused-at-b`: the amount is altered between the
   gateways; the binding to the action's material parameters refuses
   (`execution_binding_failed`).
5. `b-does-not-inherit-a-trust`: a misconfigured gateway that pins a rogue
   issuer allows an artifact; Gateway B, which does not pin that issuer,
   refuses the same bytes. VERIFIED under one set of anchors is never
   ACCEPTED under another.
6. `replay-refused-at-b`: the consumed artifact cannot drive a second
   execution (`replay_refused`).
7. `stale-status-refused-at-b`: the artifact still verifies, but the signed
   statement about whether it is *still* good is past its own `next_update`
   and past Gateway B's own freshness bound. Gateway B refuses with
   `status_stale`, refuses `status_evidence_absent` when no bundle is
   presented at all, and refuses `fresh_head_stale` for a bundle still inside
   its issuer's window but older than B's bound. A stale bundle never reads as
   current.
8. `indeterminate-does-not-reopen-a`: Gateway B enters its provider and the
   deadline passes with the outcome unresolved. Gate records the execution as
   `indeterminate`, commits the authorization instead of releasing it, refuses
   the blind retry (`replay_refused`), and leaves Gateway A's reserved leg
   byte-for-byte unchanged.

The gate instances share nothing: not a trust store, not a consumption
ledger, not an evidence log. The artifact travels; the trust does not have to.
Currency and unresolved outcomes stay with the receiver.

## What each case demonstrates

`draft-dunbar-dmsc-gw-scenarios-gap-analysis-03` §7.7 names a standardization
candidate: a mechanism-neutral interoperability profile for carrying and
verifying action-bound authorization evidence at a gateway, covering action
binding, evidence status and freshness, independent trust-anchor evaluation,
refusal behavior, replay protection, and single-use consumption. §6.9 adds
that an indeterminate outcome should not be silently retried as though the
authorization remained unused.

Each property below maps to the case that exercises it and the exact string
that case produces. Every reason in the table is returned verbatim by a
repository verifier or by Gate, with one exception: `status_evidence_absent`
is this gateway's own name for "you presented no status bundle at all", since
no verifier is reached in that path. It is named here rather than left
implicit precisely because a missing bundle must not read as a passing one.

| §7.7 property | Case | Exact reason produced |
| --- | --- | --- |
| Action binding | `tampered-in-transit-refused-at-b` | `execution_binding_failed` |
| Evidence status and freshness | `stale-status-refused-at-b` | `status_stale`; also `status_evidence_absent` when nothing is presented and `fresh_head_stale` inside the issuer's window but past B's bound |
| Independent trust-anchor evaluation | `b-does-not-inherit-a-trust` | `receipt_rejected:untrusted_or_invalid_signature` |
| Refusal behavior | `a-refuses-without-evidence`, `decision-does-not-travel` | `receipt_required` |
| Replay protection | `replay-refused-at-b` | `replay_refused` |
| Single-use consumption | `one-artifact-two-independent-verifications` | no refusal; one artifact, one execution, `executor_call_count = 1` |
| §6.9: an indeterminate outcome is not silently retried as though the authorization remained unused | `indeterminate-does-not-reopen-a` | `effect_attempted_outcome_unknown`, then `replay_refused` on the retry |

### Where the freshness and indeterminate behavior comes from

Case 7 runs at Gateway B's provider-entry boundary, the last point at which B
still owns the decision and no effect has begun. The bundle is checked twice
by two repository verifiers: `verifyStatusArtifact` (EP-STATUS-v1,
`packages/verify/src/status.ts`) decides whether the signed bundle is about
this exact artifact, from the authority B pinned, and inside its own declared
window; `evaluateCurrency` (EP-CURRENCY-v1, `packages/verify/src/currency.ts`)
then decides whether it is recent enough for *this* receiver, against Gateway
B's own `maxStalenessSeconds`. Only a bundle that passes both is admitted, and
case 2 passing through the same policy is what shows the check discriminates
rather than refusing everything. The second check is not a restatement of the
first: a bundle whose issuer gave it a twenty-minute window is still refused
`fresh_head_stale` ten minutes in, because the issuer's window is not the
receiver's bound.

Case 8 uses Gate's own post-entry path (`packages/gate/src/index.ts`, the
`run()` catch that follows provider entry). Once the effect has been entered,
an exception cannot establish that nothing happened, so Gate commits the
reservation, writes an execution record with outcome `indeterminate` and code
`effect_attempted_outcome_unknown`, and raises a terminal outcome rather than
returning a refusal a caller could mistake for "safe to retry". The lab reads
Gateway A's consumption ledger and evidence head immediately before and after
that attempt and asserts they are identical, so "the leg at A was not
reopened" is a compared value rather than a claim.

For the same behavior over a *budgeted* capability, where the thing that must
not reopen is a spend allowance rather than a single approval, see
[`examples/indeterminate-effect-reconciliation`](../indeterminate-effect-reconciliation).

## Scope and non-claims

- `draft-dunbar-dmsc-gw-scenarios-gap-analysis` is an **individual
  Internet-Draft**. It has no working-group status, and nothing here is
  adopted, endorsed, or approved by the IETF or any working group.
- This example is a **synthetic local demonstration of composition
  semantics**. It is not a conformance claim against any standard, not
  evidence of interoperability with any other implementation, and not proof of
  a real deployment.
- Every gateway, organization, settlement, and status authority in it is
  fabricated for the demo. Keys are generated at run time.
- The consumption ledgers and evidence logs are in-memory and single-process.
  They are an explicit test/demo opt-in (`allowEphemeralStore: true`); a
  deployment needs shared durable storage before any of these properties hold
  across processes.
- Verification here establishes what the artifacts and the local policy say.
  It does not establish that an external provider told the truth, and case 8
  is specifically the case where nobody knows what the provider did.

## DMSC physical-action companion

The companion scenario applies the same boundary to Sections 6.9 and 7.7 of
`draft-dunbar-dmsc-gw-scenarios-gap-analysis-02`. Port Gateway B computes an
exact crane operation, issues an action-bound challenge, and treats Gateway A
only as the carrier of a named supervisor's Class-A approval. Gateway B then
verifies under its own pinned keys and local policy, consumes the action once,
and signs a separate reliance decision that an auditor can re-perform offline.

```zsh
node examples/cross-gateway/dmsc-physical-action.mjs
```

The run allows the exact approved operation and refuses missing or revoked
approval, an expired challenge, challenge-store outage, action substitution,
an unpinned signer, challenge replay, a fresh challenge for an already-cleared
action, and mutation of the offline audit bundle. The in-memory stores are
explicitly demo-only; deployment requires shared durable stores.

Proposed DMSC text and precise non-claims are in
[`docs/standards-engagement/DMSC-ACTION-LEVEL-AUTHORIZATION.md`](../../docs/standards-engagement/DMSC-ACTION-LEVEL-AUTHORIZATION.md).
