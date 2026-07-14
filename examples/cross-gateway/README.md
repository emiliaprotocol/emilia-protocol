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

Six cases, one executor, exactly one execution:

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

The gate instances share nothing: not a trust store, not a consumption
ledger, not an evidence log. The artifact travels; the trust does not have to.
